package admin

import (
	"context"

	"github.com/smallstep/certificates/authority/config"
	"go.step.sm/crypto/jose"
	"go.step.sm/linkedca"
)

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

func CreateFirstProvisioner(ctx context.Context, db DB, password string) (*linkedca.Provisioner, error) {
	jwk, jwe, err := jose.GenerateDefaultKeyPair([]byte(password))
	if err != nil {
		return nil, WrapErrorISE(err, "error generating JWK key pair")
	}

	jwkPubBytes, err := jwk.MarshalJSON()
	if err != nil {
		return nil, WrapErrorISE(err, "error marshaling JWK")
	}
	jwePrivStr, err := jwe.CompactSerialize()
	if err != nil {
		return nil, WrapErrorISE(err, "error serializing JWE")
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
		return nil, WrapErrorISE(err, "error creating provisioner")
	}
	return p, nil
}
