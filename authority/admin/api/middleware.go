package api

import (
	"context"
	"crypto/x509"
	"net/http"
	"strings"
	"time"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/linkedca"
	"go.step.sm/crypto/jose"
)

type nextHTTP = func(http.ResponseWriter, *http.Request)

// requireAPIEnabled is a middleware that ensures the Administration API
// is enabled before servicing requests.
func (h *Handler) requireAPIEnabled(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.db == nil {
			api.WriteError(w, admin.NewError(admin.ErrorNotImplementedType,
				"administration API not enabled"))
			return
		}
		next(w, r)
	}
}

func (h *Handler) authorizeToken(r *http.Request, token string) (*linkedca.Admin, error) {
	jwt, err := jose.ParseSigned(token)
	if err != nil {
		return nil, admin.WrapError(admin.ErrorUnauthorizedType, err, "adminHandler.authorizeToken; error parsing x5c token")
	}

	verifiedChains, err := jwt.Headers[0].Certificates(x509.VerifyOptions{
		Roots: h.rootPool,
	})
	if err != nil {
		return nil, admin.WrapError(admin.ErrorUnauthorizedType, err,
			"adminHandler.authorizeToken; error verifying x5c certificate chain in token")
	}
	leaf := verifiedChains[0][0]

	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, admin.NewError(admin.ErrorUnauthorizedType, "adminHandler.authorizeToken; certificate used to sign x5c token cannot be used for digital signature")
	}

	// Using the leaf certificates key to validate the claims accomplishes two
	// things:
	//   1. Asserts that the private key used to sign the token corresponds
	//      to the public certificate in the `x5c` header of the token.
	//   2. Asserts that the claims are valid - have not been tampered with.
	var claims jose.Claims
	if err = jwt.Claims(leaf.PublicKey, &claims); err != nil {
		return nil, admin.WrapError(admin.ErrorUnauthorizedType, err, "adminHandler.authorizeToken; error parsing x5c claims")
	}

	prov, ok := h.auth.GetProvisionerCollection().LoadByCertificate(leaf)
	if !ok {
		return nil, admin.NewError(admin.ErrorUnauthorizedType, "adminHandler.authorizeToken; unable to load provisioner from x5c certificate")
	}

	// Check that the token has not been used.
	if err = h.auth.UseToken(token, prov); err != nil {
		return nil, admin.WrapError(admin.ErrorUnauthorizedType, err, "adminHandler.authorizeToken; error with reuse token")
	}

	// According to "rfc7519 JSON Web Token" acceptable skew should be no
	// more than a few minutes.
	if err = claims.ValidateWithLeeway(jose.Expected{
		Issuer: prov.GetName(),
		Time:   time.Now().UTC(),
	}, time.Minute); err != nil {
		return nil, admin.WrapError(admin.ErrorUnauthorizedType, err, "x5c.authorizeToken; invalid x5c claims")
	}

	// validate audience: path matches the current path
	if r.URL.Path != claims.Audience[0] {
		return nil, admin.NewError(admin.ErrorUnauthorizedType,
			"x5c.authorizeToken; x5c token has invalid audience "+
				"claim (aud); expected %s, but got %s", r.URL.Path, claims.Audience)
	}

	if claims.Subject == "" {
		return nil, admin.NewError(admin.ErrorUnauthorizedType,
			"x5c.authorizeToken; x5c token subject cannot be empty")
	}

	var adm *linkedca.Admin
	adminFound := false
	adminSANs := append([]string{leaf.Subject.CommonName}, leaf.DNSNames...)
	adminSANs = append(adminSANs, leaf.EmailAddresses...)
	for _, san := range adminSANs {
		if adm, ok = h.auth.GetAdminCollection().LoadBySubProv(san, claims.Issuer); ok {
			adminFound = true
			break
		}
	}
	if !adminFound {
		return nil, admin.NewError(admin.ErrorUnauthorizedType,
			"adminHandler.authorizeToken; unable to load admin with subject(s) %s and provisioner %s",
			adminSANs, claims.Issuer)
	}

	if strings.HasPrefix(r.URL.Path, "/admin/admins") && (r.Method != "GET") && adm.Type != linkedca.Admin_SUPER_ADMIN {
		return nil, admin.NewError(admin.ErrorUnauthorizedType, "must have super admin access to make this request")
	}

	return adm, nil
}

// extractAuthorizeTokenAdmin is a middleware that extracts and caches the bearer token.
func (h *Handler) extractAuthorizeTokenAdmin(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("Authorization")
		if len(tok) == 0 {
			api.WriteError(w, admin.NewError(admin.ErrorUnauthorizedType,
				"missing authorization header token"))
			return
		}

		adm, err := h.authorizeToken(r, tok)
		if err != nil {
			api.WriteError(w, err)
			return
		}

		ctx := context.WithValue(r.Context(), adminContextKey, adm)
		next(w, r.WithContext(ctx))
	}
}

// ContextKey is the key type for storing and searching for ACME request
// essentials in the context of a request.
type ContextKey string

const (
	// adminContextKey account key
	adminContextKey = ContextKey("admin")
)

/*
// adminFromContext searches the context for the token. Returns the
// token or an error.
func adminFromContext(ctx context.Context) (*linkedca.Admin, error) {
	val, ok := ctx.Value(adminContextKey).(*linkedca.Admin)
	if !ok || val == nil {
		return nil, admin.NewErrorISE("admin not in context")
	}
	return val, nil
}
*/
