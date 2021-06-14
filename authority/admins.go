package authority

import (
	"context"

	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/provisioner"
	"go.step.sm/linkedca"
)

// LoadAdminByID returns an *linkedca.Admin with the given ID.
func (a *Authority) LoadAdminByID(id string) (*linkedca.Admin, bool) {
	a.adminMutex.RLock()
	defer a.adminMutex.RUnlock()
	return a.admins.LoadByID(id)
}

// LoadAdminBySubProv returns an *linkedca.Admin with the given ID.
func (a *Authority) LoadAdminBySubProv(subject, provisioner string) (*linkedca.Admin, bool) {
	a.adminMutex.RLock()
	defer a.adminMutex.RUnlock()
	return a.admins.LoadBySubProv(subject, provisioner)
}

// GetAdmins returns a map listing each provisioner and the JWK Key Set
// with their public keys.
func (a *Authority) GetAdmins(cursor string, limit int) ([]*linkedca.Admin, string, error) {
	a.adminMutex.RLock()
	defer a.adminMutex.RUnlock()
	admins, nextCursor := a.admins.Find(cursor, limit)
	return admins, nextCursor, nil
}

// StoreAdmin stores an *linkedca.Admin to the authority.
func (a *Authority) StoreAdmin(ctx context.Context, adm *linkedca.Admin, prov provisioner.Interface) error {
	a.adminMutex.Lock()
	defer a.adminMutex.Unlock()
	if err := a.admins.Store(adm, prov); err != nil {
		return admin.WrapErrorISE(err, "error storing admin in authority cache")
	}
	// Store to database.
	if err := a.adminDB.CreateAdmin(ctx, adm); err != nil {
		// TODO remove from authority collection.
		return admin.WrapErrorISE(err, "error creating admin")
	}
	return nil
}

// UpdateAdmin stores an *linkedca.Admin to the authority.
func (a *Authority) UpdateAdmin(ctx context.Context, id string, nu *linkedca.Admin) (*linkedca.Admin, error) {
	a.adminMutex.Lock()
	defer a.adminMutex.Unlock()
	adm, err := a.admins.Update(id, nu)
	if err != nil {
		return nil, admin.WrapErrorISE(err, "error updating cached admin %s", id)
	}
	if err := a.adminDB.UpdateAdmin(ctx, adm); err != nil {
		// TODO un-update admin
		return nil, admin.WrapErrorISE(err, "error updating admin %s", id)
	}
	return adm, nil
}

// RemoveAdmin removes an *linkedca.Admin from the authority.
func (a *Authority) RemoveAdmin(ctx context.Context, id string) error {
	a.adminMutex.Lock()
	defer a.adminMutex.Unlock()

	return a.removeAdmin(ctx, id)
}

// removeAdmin helper that assumes lock.
func (a *Authority) removeAdmin(ctx context.Context, id string) error {
	if err := a.admins.Remove(id); err != nil {
		return admin.WrapErrorISE(err, "error removing admin %s from authority cache", id)
	}
	if err := a.adminDB.DeleteAdmin(ctx, id); err != nil {
		// TODO un-remove admin
		return admin.WrapErrorISE(err, "error deleting admin %s", id)
	}
	return nil
}
