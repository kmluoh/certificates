package api

import (
	"net/http"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/mgmt"
)

type nextHTTP = func(http.ResponseWriter, *http.Request)

// baseURLFromRequest is a middleware that extracts and caches the baseURL
// from the request.
// E.g. https://ca.smallstep.com/
func (h *Handler) requireAPIEnabled(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.db == nil {
			api.WriteError(w, mgmt.NewError(mgmt.ErrorNotImplementedType,
				"administration API not enabled"))
			return
		}
		next(w, r)
	}
}
