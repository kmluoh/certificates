package nosql

import (
	"context"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	nosqlDB "github.com/smallstep/nosql/database"
	"go.step.sm/crypto/randutil"
)

var (
	authorityAdminsTable       = []byte("authority_admins")
	authorityConfigsTable      = []byte("authority_configs")
	authorityProvisionersTable = []byte("authority_provisioners")
)

// DB is a struct that implements the AcmeDB interface.
type DB struct {
	db          nosqlDB.DB
	authorityID string
}

// New configures and returns a new Authority DB backend implemented using a nosql DB.
func New(db nosqlDB.DB, authorityID string) (*DB, error) {
	tables := [][]byte{authorityAdminsTable, authorityConfigsTable, authorityProvisionersTable, authorityProvisionersNameIDIndexTable}
	for _, b := range tables {
		if err := db.CreateTable(b); err != nil {
			return nil, errors.Wrapf(err, "error creating table %s",
				string(b))
		}
	}
	return &DB{db, authorityID}, nil
}

// save writes the new data to the database, overwriting the old data if it
// existed.
func (db *DB) save(ctx context.Context, id string, nu interface{}, old interface{}, typ string, table []byte) error {
	var (
		err  error
		newB []byte
	)
	if nu == nil {
		newB = nil
	} else {
		newB, err = json.Marshal(nu)
		if err != nil {
			return errors.Wrapf(err, "error marshaling authority type: %s, value: %v", typ, nu)
		}
	}
	var oldB []byte
	if old == nil {
		oldB = nil
	} else {
		oldB, err = json.Marshal(old)
		if err != nil {
			return errors.Wrapf(err, "error marshaling acme type: %s, value: %v", typ, old)
		}
	}

	_, swapped, err := db.db.CmpAndSwap(table, []byte(id), oldB, newB)
	switch {
	case err != nil:
		return errors.Wrapf(err, "error saving authority %s", typ)
	case !swapped:
		return errors.Errorf("error saving authority %s; changed since last read", typ)
	default:
		return nil
	}
}

var idLen = 32

func randID() (val string, err error) {
	val, err = randutil.UUIDv4()
	if err != nil {
		return "", errors.Wrap(err, "error generating random alphanumeric ID")
	}
	return val, nil
}

// Clock that returns time in UTC rounded to seconds.
type Clock struct{}

// Now returns the UTC time rounded to seconds.
func (c *Clock) Now() time.Time {
	return time.Now().UTC().Truncate(time.Second)
}

var clock = new(Clock)
