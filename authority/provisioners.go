package authority

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/errs"
	"go.step.sm/crypto/jose"
	"go.step.sm/linkedca"
	"gopkg.in/square/go-jose.v2/jwt"
)

// GetEncryptedKey returns the JWE key corresponding to the given kid argument.
func (a *Authority) GetEncryptedKey(kid string) (string, error) {
	a.adminMutex.RLock()
	defer a.adminMutex.RUnlock()
	key, ok := a.provisioners.LoadEncryptedKey(kid)
	if !ok {
		return "", errs.NotFound("encrypted key with kid %s was not found", kid)
	}
	return key, nil
}

// GetProvisioners returns a map listing each provisioner and the JWK Key Set
// with their public keys.
func (a *Authority) GetProvisioners(cursor string, limit int) (provisioner.List, string, error) {
	a.adminMutex.RLock()
	defer a.adminMutex.RUnlock()
	provisioners, nextCursor := a.provisioners.Find(cursor, limit)
	return provisioners, nextCursor, nil
}

// LoadProvisionerByCertificate returns an interface to the provisioner that
// provisioned the certificate.
func (a *Authority) LoadProvisionerByCertificate(crt *x509.Certificate) (provisioner.Interface, error) {
	a.adminMutex.RLock()
	defer a.adminMutex.RUnlock()
	p, ok := a.provisioners.LoadByCertificate(crt)
	if !ok {
		return nil, admin.NewError(admin.ErrorNotFoundType, "unable to load provisioner from certificate")
	}
	return p, nil
}

// LoadProvisionerByToken returns an interface to the provisioner that
// provisioned the token.
func (a *Authority) LoadProvisionerByToken(token *jwt.JSONWebToken, claims *jwt.Claims) (provisioner.Interface, error) {
	a.adminMutex.RLock()
	defer a.adminMutex.RUnlock()
	p, ok := a.provisioners.LoadByToken(token, claims)
	if !ok {
		return nil, admin.NewError(admin.ErrorNotFoundType, "unable to load provisioner from token")
	}
	return p, nil
}

// LoadProvisionerByID returns an interface to the provisioner with the given ID.
func (a *Authority) LoadProvisionerByID(id string) (provisioner.Interface, error) {
	a.adminMutex.RLock()
	defer a.adminMutex.RUnlock()
	p, ok := a.provisioners.Load(id)
	if !ok {
		return nil, admin.NewError(admin.ErrorNotFoundType, "provisioner %s not found", id)
	}
	return p, nil
}

// LoadProvisionerByName returns an interface to the provisioner with the given Name.
func (a *Authority) LoadProvisionerByName(name string) (provisioner.Interface, error) {
	a.adminMutex.RLock()
	defer a.adminMutex.RUnlock()
	p, ok := a.provisioners.LoadByName(name)
	if !ok {
		return nil, admin.NewError(admin.ErrorNotFoundType, "provisioner %s not found", name)
	}
	return p, nil
}

// StoreProvisioner stores an provisioner.Interface to the authority.
func (a *Authority) StoreProvisioner(ctx context.Context, prov *linkedca.Provisioner) error {
	a.adminMutex.Lock()
	defer a.adminMutex.Unlock()

	certProv, err := ProvisionerToCertificates(prov)
	if err != nil {
		return admin.WrapErrorISE(err,
			"error converting to certificates provisioner from linkedca provisioner")
	}

	if err := a.provisioners.Store(certProv); err != nil {
		return admin.WrapErrorISE(err, "error storing provisioner in authority cache")
	}
	// Store to database.
	if err := a.adminDB.CreateProvisioner(ctx, prov); err != nil {
		// TODO remove from authority collection.
		return admin.WrapErrorISE(err, "error creating admin")
	}
	return nil
}

// UpdateProvisioner stores an provisioner.Interface to the authority.
func (a *Authority) UpdateProvisioner(ctx context.Context, id string, nu *linkedca.Provisioner) error {
	a.adminMutex.Lock()
	defer a.adminMutex.Unlock()

	certProv, err := ProvisionerToCertificates(nu)
	if err != nil {
		return admin.WrapErrorISE(err,
			"error converting to certificates provisioner from linkedca provisioner")
	}

	if err := a.provisioners.Update(id, certProv); err != nil {
		return admin.WrapErrorISE(err, "error updating provisioner '%s' in authority cache", nu.Name)
	}
	if err := a.adminDB.UpdateProvisioner(ctx, nu); err != nil {
		// TODO un-update provisioner
		return admin.WrapErrorISE(err, "error updating provisioner '%s'", nu.Name)
	}
	return nil
}

// RemoveProvisioner removes an provisioner.Interface from the authority.
func (a *Authority) RemoveProvisioner(ctx context.Context, id string) error {
	a.adminMutex.Lock()
	defer a.adminMutex.Unlock()

	p, ok := a.provisioners.Load(id)
	if !ok {
		return admin.NewError(admin.ErrorBadRequestType,
			"provisioner %s not found", id)
	}

	provName, provID := p.GetName(), p.GetID()
	// Validate
	//  - Check that there will be SUPER_ADMINs that remain after we
	//    remove this provisioner.
	if a.admins.SuperCount() == a.admins.SuperCountByProvisioner(provName) {
		return admin.NewError(admin.ErrorBadRequestType,
			"cannot remove provisioner %s because no super admins will remain", provName)
	}

	// Delete all admins associated with the provisioner.
	admins, ok := a.admins.LoadByProvisioner(provName)
	if ok {
		for _, adm := range admins {
			if err := a.removeAdmin(ctx, adm.Id); err != nil {
				return admin.WrapErrorISE(err, "error deleting admin %s, as part of provisioner %s deletion", adm.Subject, provName)
			}
		}
	}

	// Remove provisioner from authority caches.
	if err := a.provisioners.Remove(provID); err != nil {
		return admin.WrapErrorISE(err, "error removing admin from authority cache")
	}
	// Remove provisione from database.
	if err := a.adminDB.DeleteProvisioner(ctx, provID); err != nil {
		// TODO un-remove provisioner from collection
		return admin.WrapErrorISE(err, "error deleting provisioner %s", provName)
	}
	return nil
}

func CreateFirstProvisioner(ctx context.Context, db admin.DB, password string) (*linkedca.Provisioner, error) {
	jwk, jwe, err := jose.GenerateDefaultKeyPair([]byte(password))
	if err != nil {
		return nil, admin.WrapErrorISE(err, "error generating JWK key pair")
	}

	jwkPubBytes, err := jwk.MarshalJSON()
	if err != nil {
		return nil, admin.WrapErrorISE(err, "error marshaling JWK")
	}
	jwePrivStr, err := jwe.CompactSerialize()
	if err != nil {
		return nil, admin.WrapErrorISE(err, "error serializing JWE")
	}

	p := &linkedca.Provisioner{
		Name:   "Admin JWK",
		Type:   linkedca.Provisioner_JWK,
		Claims: NewDefaultClaims(),
		Details: &linkedca.ProvisionerDetails{
			Data: &linkedca.ProvisionerDetails_JWK{
				JWK: &linkedca.JWKProvisioner{
					PublicKey:           jwkPubBytes,
					EncryptedPrivateKey: []byte(jwePrivStr),
				},
			},
		},
	}
	if err := db.CreateProvisioner(ctx, p); err != nil {
		return nil, admin.WrapErrorISE(err, "error creating provisioner")
	}
	return p, nil
}

func NewDefaultClaims() *linkedca.Claims {
	return &linkedca.Claims{
		X509: &linkedca.X509Claims{
			Durations: &linkedca.Durations{
				Min:     config.GlobalProvisionerClaims.MinTLSDur.String(),
				Max:     config.GlobalProvisionerClaims.MaxTLSDur.String(),
				Default: config.GlobalProvisionerClaims.DefaultTLSDur.String(),
			},
		},
		Ssh: &linkedca.SSHClaims{
			UserDurations: &linkedca.Durations{
				Min:     config.GlobalProvisionerClaims.MinUserSSHDur.String(),
				Max:     config.GlobalProvisionerClaims.MaxUserSSHDur.String(),
				Default: config.GlobalProvisionerClaims.DefaultUserSSHDur.String(),
			},
			HostDurations: &linkedca.Durations{
				Min:     config.GlobalProvisionerClaims.MinHostSSHDur.String(),
				Max:     config.GlobalProvisionerClaims.MaxHostSSHDur.String(),
				Default: config.GlobalProvisionerClaims.DefaultHostSSHDur.String(),
			},
		},
		DisableRenewal: config.DefaultDisableRenewal,
	}
}

func provisionerListToCertificates(l []*linkedca.Provisioner) (provisioner.List, error) {
	var nu provisioner.List
	for _, p := range l {
		certProv, err := ProvisionerToCertificates(p)
		if err != nil {
			return nil, err
		}
		nu = append(nu, certProv)
	}
	return nu, nil
}

func optionsToCertificates(p *linkedca.Provisioner) *provisioner.Options {
	ops := &provisioner.Options{
		X509: &provisioner.X509Options{},
		SSH:  &provisioner.SSHOptions{},
	}
	if p.X509Template != nil {
		ops.X509.Template = string(p.X509Template.Template)
		ops.X509.TemplateData = p.X509Template.Data
	}
	if p.SshTemplate != nil {
		ops.SSH.Template = string(p.SshTemplate.Template)
		ops.SSH.TemplateData = p.SshTemplate.Data
	}
	return ops
}

// claimsToCertificates converts the linkedca provisioner claims type to the
// certifictes claims type.
func claimsToCertificates(c *linkedca.Claims) (*provisioner.Claims, error) {
	if c == nil {
		return nil, nil
	}

	pc := &provisioner.Claims{
		DisableRenewal: &c.DisableRenewal,
	}

	var err error

	if xc := c.X509; xc != nil {
		if d := xc.Durations; d != nil {
			if len(d.Min) > 0 {
				pc.MinTLSDur, err = provisioner.NewDuration(d.Min)
				if err != nil {
					return nil, admin.WrapErrorISE(err, "error parsing claims.minTLSDur: %s", d.Min)
				}
			}
			if len(d.Max) > 0 {
				pc.MaxTLSDur, err = provisioner.NewDuration(d.Max)
				if err != nil {
					return nil, admin.WrapErrorISE(err, "error parsing claims.maxTLSDur: %s", d.Max)
				}
			}
			if len(d.Default) > 0 {
				pc.DefaultTLSDur, err = provisioner.NewDuration(d.Default)
				if err != nil {
					return nil, admin.WrapErrorISE(err, "error parsing claims.defaultTLSDur: %s", d.Default)
				}
			}
		}
	}
	if sc := c.Ssh; sc != nil {
		pc.EnableSSHCA = &sc.Enabled
		if d := sc.UserDurations; d != nil {
			if len(d.Min) > 0 {
				pc.MinUserSSHDur, err = provisioner.NewDuration(d.Min)
				if err != nil {
					return nil, admin.WrapErrorISE(err, "error parsing claims.minUserSSHDur: %s", d.Min)
				}
			}
			if len(d.Max) > 0 {
				pc.MaxUserSSHDur, err = provisioner.NewDuration(d.Max)
				if err != nil {
					return nil, admin.WrapErrorISE(err, "error parsing claims.maxUserSSHDur: %s", d.Max)
				}
			}
			if len(d.Default) > 0 {
				pc.DefaultUserSSHDur, err = provisioner.NewDuration(d.Default)
				if err != nil {
					return nil, admin.WrapErrorISE(err, "error parsing claims.defaultUserSSHDur: %s", d.Default)
				}
			}
		}
		if d := sc.HostDurations; d != nil {
			if len(d.Min) > 0 {
				pc.MinHostSSHDur, err = provisioner.NewDuration(d.Min)
				if err != nil {
					return nil, admin.WrapErrorISE(err, "error parsing claims.minHostSSHDur: %s", d.Min)
				}
			}
			if len(d.Max) > 0 {
				pc.MaxHostSSHDur, err = provisioner.NewDuration(d.Max)
				if err != nil {
					return nil, admin.WrapErrorISE(err, "error parsing claims.maxHostSSHDur: %s", d.Max)
				}
			}
			if len(d.Default) > 0 {
				pc.DefaultHostSSHDur, err = provisioner.NewDuration(d.Default)
				if err != nil {
					return nil, admin.WrapErrorISE(err, "error parsing claims.defaultHostSSHDur: %s", d.Default)
				}
			}
		}
	}

	return pc, nil
}

// ProvisionerToCertificates converts the linkedca provisioner type to the certificates provisioner
// interface.
func ProvisionerToCertificates(p *linkedca.Provisioner) (provisioner.Interface, error) {
	claims, err := claimsToCertificates(p.Claims)
	if err != nil {
		return nil, err
	}

	details := p.Details.GetData()
	if details == nil {
		return nil, fmt.Errorf("provisioner does not have any details")
	}

	options := optionsToCertificates(p)

	switch d := details.(type) {
	case *linkedca.ProvisionerDetails_JWK:
		jwk := new(jose.JSONWebKey)
		if err := json.Unmarshal(d.JWK.PublicKey, &jwk); err != nil {
			return nil, err
		}
		return &provisioner.JWK{
			ID:           p.Id,
			Type:         p.Type.String(),
			Name:         p.Name,
			Key:          jwk,
			EncryptedKey: string(d.JWK.EncryptedPrivateKey),
			Claims:       claims,
			Options:      options,
		}, nil
	case *linkedca.ProvisionerDetails_X5C:
		var roots []byte
		for i, root := range d.X5C.GetRoots() {
			if i > 0 {
				roots = append(roots, '\n')
			}
			roots = append(roots, root...)
		}
		return &provisioner.X5C{
			ID:      p.Id,
			Type:    p.Type.String(),
			Name:    p.Name,
			Roots:   roots,
			Claims:  claims,
			Options: options,
		}, nil
	case *linkedca.ProvisionerDetails_K8SSA:
		var publicKeys []byte
		for i, k := range d.K8SSA.GetPublicKeys() {
			if i > 0 {
				publicKeys = append(publicKeys, '\n')
			}
			publicKeys = append(publicKeys, k...)
		}
		return &provisioner.K8sSA{
			ID:      p.Id,
			Type:    p.Type.String(),
			Name:    p.Name,
			PubKeys: publicKeys,
			Claims:  claims,
			Options: options,
		}, nil
	case *linkedca.ProvisionerDetails_SSHPOP:
		return &provisioner.SSHPOP{
			ID:     p.Id,
			Type:   p.Type.String(),
			Name:   p.Name,
			Claims: claims,
		}, nil
	case *linkedca.ProvisionerDetails_ACME:
		cfg := d.ACME
		return &provisioner.ACME{
			ID:      p.Id,
			Type:    p.Type.String(),
			Name:    p.Name,
			ForceCN: cfg.ForceCn,
			Claims:  claims,
			Options: options,
		}, nil
	case *linkedca.ProvisionerDetails_OIDC:
		cfg := d.OIDC
		return &provisioner.OIDC{
			ID:                    p.Id,
			Type:                  p.Type.String(),
			Name:                  p.Name,
			TenantID:              cfg.TenantId,
			ClientID:              cfg.ClientId,
			ClientSecret:          cfg.ClientSecret,
			ConfigurationEndpoint: cfg.ConfigurationEndpoint,
			Admins:                cfg.Admins,
			Domains:               cfg.Domains,
			Groups:                cfg.Groups,
			ListenAddress:         cfg.ListenAddress,
			Claims:                claims,
			Options:               options,
		}, nil
	case *linkedca.ProvisionerDetails_AWS:
		cfg := d.AWS
		instanceAge, err := parseInstanceAge(cfg.InstanceAge)
		if err != nil {
			return nil, err
		}
		return &provisioner.AWS{
			ID:                     p.Id,
			Type:                   p.Type.String(),
			Name:                   p.Name,
			Accounts:               cfg.Accounts,
			DisableCustomSANs:      cfg.DisableCustomSans,
			DisableTrustOnFirstUse: cfg.DisableTrustOnFirstUse,
			InstanceAge:            instanceAge,
			Claims:                 claims,
			Options:                options,
		}, nil
		// TODO add GCP, Azure, and SCEP
		/*
			case *ProvisionerDetails_GCP:
				cfg := d.GCP
				return &provisioner.GCP{
					Type:                   p.Type.String(),
					Name:                   p.Name,
					ServiceAccounts:        cfg.ServiceAccounts,
					ProjectIDs:             cfg.ProjectIds,
					DisableCustomSANs:      cfg.DisableCustomSans,
					DisableTrustOnFirstUse: cfg.DisableTrustOnFirstUse,
					InstanceAge:            durationValue(cfg.InstanceAge),
					Claims:                 claims,
					Options:                options,
				}, nil
			case *ProvisionerDetails_Azure:
				cfg := d.Azure
				return &provisioner.Azure{
					Type:                   p.Type.String(),
					Name:                   p.Name,
					TenantID:               cfg.TenantId,
					ResourceGroups:         cfg.ResourceGroups,
					Audience:               cfg.Audience,
					DisableCustomSANs:      cfg.DisableCustomSans,
					DisableTrustOnFirstUse: cfg.DisableTrustOnFirstUse,
					Claims:                 claims,
					Options:                options,
				}, nil
		*/
	default:
		return nil, fmt.Errorf("provisioner %s not implemented", p.Type)
	}
}

func parseInstanceAge(age string) (provisioner.Duration, error) {
	var instanceAge provisioner.Duration
	if age != "" {
		iap, err := provisioner.NewDuration(age)
		if err != nil {
			return instanceAge, err
		}
		instanceAge = *iap
	}
	return instanceAge, nil
}
