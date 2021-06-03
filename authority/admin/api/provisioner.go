package api

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/certificates/linkedca"
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
		p  provisioner.Interface
		ok bool
	)
	if len(id) > 0 {
		if p, ok = h.auth.GetProvisionerClxn().Load(id); !ok {
			api.WriteError(w, admin.NewError(admin.ErrorNotFoundType, "provisioner %s not found", name))
			return
		}
	} else {
		if p, ok = h.auth.GetProvisionerClxn().LoadByName(name); !ok {
			api.WriteError(w, admin.NewError(admin.ErrorNotFoundType, "provisioner %s not found", id))
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

// GetProvisioners returns all provisioners associated with the authority.
func (h *Handler) GetProvisioners(w http.ResponseWriter, r *http.Request) {
	cursor, limit, err := api.ParseCursor(r)
	if err != nil {
		api.WriteError(w, admin.WrapError(admin.ErrorBadRequestType, err,
			"error parsing cursor / limt query params"))
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
	ctx := r.Context()

	var prov = new(linkedca.Provisioner)
	if err := api.ReadProtoJSON(r.Body, prov); err != nil {
		api.WriteError(w, err)
		return
	}

	// TODO: validate
	clxn := h.auth.GetProvisionerClxn()
	if _, ok := clxn.LoadByName(prov.Name); ok {
		api.WriteError(w, admin.NewError(admin.ErrorBadRequestType,
			"provisioner with name %s already exists", prov.Name))
		return
	}
	certProv, err := authority.ProvisionerToCertificates(prov)
	if err != nil {
		api.WriteError(w, admin.WrapErrorISE(err, "error converting from linkedca provisioner"))
		return
	}
	if _, ok := clxn.LoadByTokenID(certProv.GetIDForToken()); ok {
		api.WriteError(w, admin.NewError(admin.ErrorBadRequestType,
			"provisioner with token-id %s already exists", certProv.GetIDForToken()))
		return
	}

	// TODO: fix this
	prov.Claims = admin.NewDefaultClaims()

	if err := h.db.CreateProvisioner(ctx, prov); err != nil {
		api.WriteError(w, err)
		return
	}
	api.ProtoJSONStatus(w, prov, http.StatusCreated)

	if err := h.auth.ReloadAuthConfig(ctx); err != nil {
		fmt.Printf("err = %+v\n", err)
	}
}

// DeleteProvisioner deletes a provisioner.
func (h *Handler) DeleteProvisioner(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	name := chi.URLParam(r, "name")

	var (
		p  provisioner.Interface
		ok bool
	)
	if len(id) > 0 {
		if p, ok = h.auth.GetProvisionerClxn().Load(id); !ok {
			api.WriteError(w, admin.NewError(admin.ErrorNotFoundType, "provisioner %s not found", id))
			return
		}
	} else {
		if p, ok = h.auth.GetProvisionerClxn().LoadByName(name); !ok {
			api.WriteError(w, admin.NewError(admin.ErrorNotFoundType, "provisioner %s not found", name))
			return
		}
	}

	// Validate
	//  - Check that there are SUPER_ADMINs that aren't associated with this provisioner.
	c := h.auth.GetAdminClxn()
	if c.SuperCount() == c.SuperCountByProvisioner(p.GetName()) {
		api.WriteError(w, admin.NewError(admin.ErrorBadRequestType,
			"cannot remove provisioner %s because no super admins will remain", name))
		return
	}

	ctx := r.Context()
	if err := h.db.DeleteProvisioner(ctx, p.GetID()); err != nil {
		api.WriteError(w, admin.WrapErrorISE(err, "error deleting provisioner %s", name))
		return
	}

	// Delete all admins associated with the provisioner.
	admins, ok := c.LoadByProvisioner(name)
	if ok {
		for _, adm := range admins {
			if err := h.db.DeleteAdmin(ctx, adm.Id); err != nil {
				api.WriteError(w, admin.WrapErrorISE(err, "error deleting admin %s, as part of provisioner %s deletion", adm.Subject, name))
				return
			}
		}
	}

	api.JSON(w, &DeleteResponse{Status: "ok"})

	if err := h.auth.ReloadAuthConfig(ctx); err != nil {
		fmt.Printf("err = %+v\n", err)
	}
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
