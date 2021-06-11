package authority

import (
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/errs"
	"go.step.sm/crypto/jose"
	"go.step.sm/linkedca"
)

// GetEncryptedKey returns the JWE key corresponding to the given kid argument.
func (a *Authority) GetEncryptedKey(kid string) (string, error) {
	key, ok := a.GetProvisionerClxn().LoadEncryptedKey(kid)
	if !ok {
		return "", errs.NotFound("encrypted key with kid %s was not found", kid)
	}
	return key, nil
}

// GetProvisioners returns a map listing each provisioner and the JWK Key Set
// with their public keys.
func (a *Authority) GetProvisioners(cursor string, limit int) (provisioner.List, string, error) {
	provisioners, nextCursor := a.GetProvisionerClxn().Find(cursor, limit)
	return provisioners, nextCursor, nil
}

// LoadProvisionerByCertificate returns an interface to the provisioner that
// provisioned the certificate.
func (a *Authority) LoadProvisionerByCertificate(crt *x509.Certificate) (provisioner.Interface, error) {
	p, ok := a.GetProvisionerClxn().LoadByCertificate(crt)
	if !ok {
		return nil, errs.NotFound("provisioner not found")
	}
	return p, nil
}

// LoadProvisionerByName returns an interface to the provisioner with the given ID.
func (a *Authority) LoadProvisionerByName(name string) (provisioner.Interface, error) {
	p, ok := a.GetProvisionerClxn().LoadByName(name)
	if !ok {
		return nil, errs.NotFound("provisioner %s not found", name)
	}
	return p, nil
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
	return &provisioner.Options{
		X509: &provisioner.X509Options{
			Template:     string(p.X509Template.Template),
			TemplateData: p.X509Template.Data,
		},
		SSH: &provisioner.SSHOptions{
			Template:     string(p.SshTemplate.Template),
			TemplateData: p.SshTemplate.Data,
		},
	}
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
