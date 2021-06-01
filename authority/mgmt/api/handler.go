package api

import (
	"crypto/x509"
	"time"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/mgmt"
)

// Clock that returns time in UTC rounded to seconds.
type Clock struct{}

// Now returns the UTC time rounded to seconds.
func (c *Clock) Now() time.Time {
	return time.Now().UTC().Truncate(time.Second)
}

var clock Clock

// Handler is the ACME API request handler.
type Handler struct {
	db       mgmt.DB
	auth     *authority.Authority
	rootPool *x509.CertPool
}

// NewHandler returns a new Authority Config Handler.
func NewHandler(auth *authority.Authority) api.RouterHandler {
	h := &Handler{db: auth.GetAdminDatabase(), auth: auth}

	h.rootPool = x509.NewCertPool()
	for _, cert := range auth.GetRootX509Certs() {
		h.rootPool.AddCert(cert)
	}

	return h
}

// Route traffic and implement the Router interface.
func (h *Handler) Route(r api.Router) {
	authnz := func(next nextHTTP) nextHTTP {
		return h.extractAuthorizeTokenAdmin(h.requireAPIEnabled(next))
	}

	// Provisioners
	r.MethodFunc("GET", "/provisioners/{name}", authnz(h.GetProvisioner))
	r.MethodFunc("GET", "/provisioners", authnz(h.GetProvisioners))
	r.MethodFunc("POST", "/provisioners", authnz(h.CreateProvisioner))
	r.MethodFunc("PUT", "/provisioners/{name}", authnz(h.UpdateProvisioner))
	r.MethodFunc("DELETE", "/provisioners/{name}", authnz(h.DeleteProvisioner))

	// Admins
	r.MethodFunc("GET", "/admins/{id}", authnz(h.GetAdmin))
	r.MethodFunc("GET", "/admins", authnz(h.GetAdmins))
	r.MethodFunc("POST", "/admins", authnz(h.CreateAdmin))
	r.MethodFunc("PATCH", "/admins/{id}", authnz(h.UpdateAdmin))
	r.MethodFunc("DELETE", "/admins/{id}", authnz(h.DeleteAdmin))
}
