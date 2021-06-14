package api

import (
	"net/http"

	"github.com/go-chi/chi"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/errs"
	"go.step.sm/linkedca"
)

// GetProvisionersResponse is the type for GET /admin/provisioners responses.
type GetProvisionersResponse struct {
	Provisioners provisioner.List `json:"provisioners"`
	NextCursor   string           `json:"nextCursor"`
}

// UpdateProvisionerRequest represents the body for a UpdateProvisioner request.
type UpdateProvisionerRequest struct {
	Type             string           `json:"type"`
	Name             string           `json:"name"`
	Claims           *linkedca.Claims `json:"claims"`
	Details          []byte           `json:"details"`
	X509Template     string           `json:"x509Template"`
	X509TemplateData []byte           `json:"x509TemplateData"`
	SSHTemplate      string           `json:"sshTemplate"`
	SSHTemplateData  []byte           `json:"sshTemplateData"`
}

// Validate validates a update-provisioner request body.
func (upr *UpdateProvisionerRequest) Validate(c *provisioner.Collection) error {
	if _, ok := c.LoadByName(upr.Name); ok {
		return admin.NewError(admin.ErrorBadRequestType, "provisioner with name %s already exists", upr.Name)
	}
	return nil
}

// GetProvisioner returns the requested provisioner, or an error.
func (h *Handler) GetProvisioner(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := r.URL.Query().Get("id")
	name := chi.URLParam(r, "name")

	var (
		p   provisioner.Interface
		err error
	)
	if len(id) > 0 {
		if p, err = h.auth.LoadProvisionerByID(id); err != nil {
			api.WriteError(w, admin.WrapErrorISE(err, "error loading provisioner %s", id))
			return
		}
	} else {
		if p, err = h.auth.LoadProvisionerByName(name); err != nil {
			api.WriteError(w, admin.WrapErrorISE(err, "error loading provisioner %s", name))
			return
		}
	}

	prov, err := h.db.GetProvisioner(ctx, p.GetID())
	if err != nil {
		api.WriteError(w, err)
		return
	}
	api.ProtoJSON(w, prov)
}

// GetProvisioners returns the given segment of  provisioners associated with the authority.
func (h *Handler) GetProvisioners(w http.ResponseWriter, r *http.Request) {
	cursor, limit, err := api.ParseCursor(r)
	if err != nil {
		api.WriteError(w, admin.WrapError(admin.ErrorBadRequestType, err,
			"error parsing cursor & limit query params"))
		return
	}

	p, next, err := h.auth.GetProvisioners(cursor, limit)
	if err != nil {
		api.WriteError(w, errs.InternalServerErr(err))
		return
	}
	api.JSON(w, &GetProvisionersResponse{
		Provisioners: p,
		NextCursor:   next,
	})
}

// CreateProvisioner creates a new prov.
func (h *Handler) CreateProvisioner(w http.ResponseWriter, r *http.Request) {
	var prov = new(linkedca.Provisioner)
	if err := api.ReadProtoJSON(r.Body, prov); err != nil {
		api.WriteError(w, err)
		return
	}

	// TODO: fix this
	prov.Claims = authority.NewDefaultClaims()
	// TODO: validate

	if err := h.auth.StoreProvisioner(r.Context(), prov); err != nil {
		api.WriteError(w, admin.WrapErrorISE(err, "error storing provisioner %s", prov.Name))
		return
	}
	api.ProtoJSONStatus(w, prov, http.StatusCreated)
}

// DeleteProvisioner deletes a provisioner.
func (h *Handler) DeleteProvisioner(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	name := chi.URLParam(r, "name")

	var (
		p   provisioner.Interface
		err error
	)
	if len(id) > 0 {
		if p, err = h.auth.LoadProvisionerByID(id); err != nil {
			api.WriteError(w, admin.WrapErrorISE(err, "error loading provisioner %s", id))
			return
		}
	} else {
		if p, err = h.auth.LoadProvisionerByName(name); err != nil {
			api.WriteError(w, admin.WrapErrorISE(err, "error loading provisioner %s", name))
			return
		}
	}

	if err := h.auth.RemoveProvisioner(r.Context(), p.GetID()); err != nil {
		api.WriteError(w, admin.WrapErrorISE(err, "error removing provisioner %s", p.GetName()))
		return
	}

	api.JSON(w, &DeleteResponse{Status: "ok"})
}

// UpdateProvisioner updates an existing prov.
func (h *Handler) UpdateProvisioner(w http.ResponseWriter, r *http.Request) {
	/*
		ctx := r.Context()
		id := chi.URLParam(r, "id")

		var body UpdateProvisionerRequest
		if err := ReadJSON(r.Body, &body); err != nil {
			api.WriteError(w, err)
			return
		}
		if err := body.Validate(); err != nil {
			api.WriteError(w, err)
			return
		}
		if prov, err := h.db.GetProvisioner(ctx, id); err != nil {
			api.WriteError(w, err)
			return
		}

		prov.Claims = body.Claims
		prov.Details = body.Provisioner
		prov.X509Template = body.X509Template
		prov.SSHTemplate = body.SSHTemplate
		prov.Status = body.Status

		if err := h.db.UpdateProvisioner(ctx, prov); err != nil {
			api.WriteError(w, err)
			return
		}
		api.JSON(w, prov)
	*/
}
