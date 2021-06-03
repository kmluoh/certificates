package administrator

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/linkedca"
)

// DefaultAdminLimit is the default limit for listing provisioners.
const DefaultAdminLimit = 20

// DefaultAdminMax is the maximum limit for listing provisioners.
const DefaultAdminMax = 100

type uidAdmin struct {
	admin *linkedca.Admin
	uid   string
}

type adminSlice []uidAdmin

func (p adminSlice) Len() int           { return len(p) }
func (p adminSlice) Less(i, j int) bool { return p[i].uid < p[j].uid }
func (p adminSlice) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

// Collection is a memory map of admins.
type Collection struct {
	byID                    *sync.Map
	bySubProv               *sync.Map
	byProv                  *sync.Map
	sorted                  adminSlice
	provisioners            *provisioner.Collection
	superCount              int
	superCountByProvisioner map[string]int
}

// NewCollection initializes a collection of provisioners. The given list of
// audiences are the audiences used by the JWT provisioner.
func NewCollection(provisioners *provisioner.Collection) *Collection {
	return &Collection{
		byID:                    new(sync.Map),
		byProv:                  new(sync.Map),
		bySubProv:               new(sync.Map),
		superCountByProvisioner: map[string]int{},
		provisioners:            provisioners,
	}
}

// LoadByID a admin by the ID.
func (c *Collection) LoadByID(id string) (*linkedca.Admin, bool) {
	return loadAdmin(c.byID, id)
}

type subProv struct {
	subject     string
	provisioner string
}

func newSubProv(subject, provisioner string) subProv {
	return subProv{subject, provisioner}
}

// LoadBySubProv a admin by the subject and provisioner name.
func (c *Collection) LoadBySubProv(sub, provName string) (*linkedca.Admin, bool) {
	return loadAdmin(c.bySubProv, newSubProv(sub, provName))
}

// LoadByProvisioner a admin by the subject and provisioner name.
func (c *Collection) LoadByProvisioner(provName string) ([]*linkedca.Admin, bool) {
	val, ok := c.byProv.Load(provName)
	if !ok {
		return nil, false
	}
	admins, ok := val.([]*linkedca.Admin)
	if !ok {
		return nil, false
	}
	return admins, true
}

// Store adds an admin to the collection and enforces the uniqueness of
// admin IDs and amdin subject <-> provisioner name combos.
func (c *Collection) Store(adm *linkedca.Admin) error {
	p, ok := c.provisioners.Load(adm.ProvisionerId)
	if !ok {
		return fmt.Errorf("provisioner %s not found", adm.ProvisionerId)
	}
	// Store admin always in byID. ID must be unique.
	if _, loaded := c.byID.LoadOrStore(adm.Id, adm); loaded {
		return errors.New("cannot add multiple admins with the same id")
	}

	provName := p.GetName()
	// Store admin always in bySubProv. Subject <-> ProvisionerName must be unique.
	if _, loaded := c.bySubProv.LoadOrStore(newSubProv(adm.Subject, provName), adm); loaded {
		c.byID.Delete(adm.Id)
		return errors.New("cannot add multiple admins with the same subject and provisioner")
	}

	if admins, ok := c.LoadByProvisioner(provName); ok {
		c.byProv.Store(provName, append(admins, adm))
		c.superCountByProvisioner[provName]++
	} else {
		c.byProv.Store(provName, []*linkedca.Admin{adm})
		c.superCountByProvisioner[provName] = 1
	}
	c.superCount++

	// Store sorted admins.
	// Use the first 4 bytes (32bit) of the sum to insert the order
	// Using big endian format to get the strings sorted:
	// 0x00000000, 0x00000001, 0x00000002, ...
	bi := make([]byte, 4)
	_sum := sha1.Sum([]byte(adm.Id))
	sum := _sum[:]
	binary.BigEndian.PutUint32(bi, uint32(c.sorted.Len()))
	sum[0], sum[1], sum[2], sum[3] = bi[0], bi[1], bi[2], bi[3]
	c.sorted = append(c.sorted, uidAdmin{
		admin: adm,
		uid:   hex.EncodeToString(sum),
	})
	sort.Sort(c.sorted)

	return nil
}

// SuperCount returns the total number of admins.
func (c *Collection) SuperCount() int {
	return c.superCount
}

// SuperCountByProvisioner returns the total number of admins.
func (c *Collection) SuperCountByProvisioner(provName string) int {
	if cnt, ok := c.superCountByProvisioner[provName]; ok {
		return cnt
	}
	return 0
}

// Find implements pagination on a list of sorted provisioners.
func (c *Collection) Find(cursor string, limit int) ([]*linkedca.Admin, string) {
	switch {
	case limit <= 0:
		limit = DefaultAdminLimit
	case limit > DefaultAdminMax:
		limit = DefaultAdminMax
	}

	n := c.sorted.Len()
	cursor = fmt.Sprintf("%040s", cursor)
	i := sort.Search(n, func(i int) bool { return c.sorted[i].uid >= cursor })

	slice := []*linkedca.Admin{}
	for ; i < n && len(slice) < limit; i++ {
		slice = append(slice, c.sorted[i].admin)
	}

	if i < n {
		return slice, strings.TrimLeft(c.sorted[i].uid, "0")
	}
	return slice, ""
}

func loadAdmin(m *sync.Map, key interface{}) (*linkedca.Admin, bool) {
	val, ok := m.Load(key)
	if !ok {
		return nil, false
	}
	adm, ok := val.(*linkedca.Admin)
	if !ok {
		return nil, false
	}
	return adm, true
}
