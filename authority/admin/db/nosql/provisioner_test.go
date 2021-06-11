package nosql

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/nosql"
	nosqldb "github.com/smallstep/nosql/database"
	"go.step.sm/linkedca"
)

func TestDB_getDBProvisionerBytes(t *testing.T) {
	provID := "provID"
	type test struct {
		db       nosql.DB
		err      error
		adminErr *admin.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return nil, nosqldb.ErrNotFound
					},
				},
				adminErr: admin.NewError(admin.ErrorNotFoundType, "provisioner provID not found"),
			}
		},
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading provisioner provID: force"),
			}
		},
		"ok": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return []byte("foo"), nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			db := DB{db: tc.db}
			if b, err := db.getDBProvisionerBytes(context.Background(), provID); err != nil {
				switch k := err.(type) {
				case *admin.Error:
					if assert.NotNil(t, tc.adminErr) {
						assert.Equals(t, k.Type, tc.adminErr.Type)
						assert.Equals(t, k.Detail, tc.adminErr.Detail)
						assert.Equals(t, k.Status, tc.adminErr.Status)
						assert.Equals(t, k.Err.Error(), tc.adminErr.Err.Error())
						assert.Equals(t, k.Detail, tc.adminErr.Detail)
					}
				default:
					if assert.NotNil(t, tc.err) {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, string(b), "foo")
				}
			}
		})
	}
}

func TestDB_getDBProvisioner(t *testing.T) {
	provID := "provID"
	type test struct {
		db       nosql.DB
		err      error
		adminErr *admin.Error
		dbp      *dbProvisioner
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return nil, nosqldb.ErrNotFound
					},
				},
				adminErr: admin.NewError(admin.ErrorNotFoundType, "provisioner provID not found"),
			}
		},
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading provisioner provID: force"),
			}
		},
		"fail/unmarshal-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return []byte("foo"), nil
					},
				},
				err: errors.New("error unmarshaling provisioner provID into dbProvisioner"),
			}
		},
		"fail/deleted": func(t *testing.T) test {
			now := clock.Now()
			dbp := &dbProvisioner{
				ID:          provID,
				AuthorityID: admin.DefaultAuthorityID,
				Type:        linkedca.Provisioner_JWK,
				Name:        "provName",
				CreatedAt:   now,
				DeletedAt:   now,
			}
			b, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return b, nil
					},
				},
				adminErr: admin.NewError(admin.ErrorDeletedType, "provisioner provID is deleted"),
			}
		},
		"ok": func(t *testing.T) test {
			now := clock.Now()
			dbp := &dbProvisioner{
				ID:          provID,
				AuthorityID: admin.DefaultAuthorityID,
				Type:        linkedca.Provisioner_JWK,
				Name:        "provName",
				CreatedAt:   now,
			}
			b, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return b, nil
					},
				},
				dbp: dbp,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			db := DB{db: tc.db, authorityID: admin.DefaultAuthorityID}
			if dbp, err := db.getDBProvisioner(context.Background(), provID); err != nil {
				switch k := err.(type) {
				case *admin.Error:
					if assert.NotNil(t, tc.adminErr) {
						assert.Equals(t, k.Type, tc.adminErr.Type)
						assert.Equals(t, k.Detail, tc.adminErr.Detail)
						assert.Equals(t, k.Status, tc.adminErr.Status)
						assert.Equals(t, k.Err.Error(), tc.adminErr.Err.Error())
						assert.Equals(t, k.Detail, tc.adminErr.Detail)
					}
				default:
					if assert.NotNil(t, tc.err) {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, dbp.ID, provID)
					assert.Equals(t, dbp.AuthorityID, tc.dbp.AuthorityID)
					assert.Equals(t, dbp.Type, tc.dbp.Type)
					assert.Equals(t, dbp.Name, tc.dbp.Name)
					assert.Equals(t, dbp.CreatedAt, tc.dbp.CreatedAt)
					assert.Fatal(t, dbp.DeletedAt.IsZero())
				}
			}
		})
	}
}

func TestDB_unmarshalDBProvisioner(t *testing.T) {
	provID := "provID"
	type test struct {
		in       []byte
		err      error
		adminErr *admin.Error
		dbp      *dbProvisioner
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/unmarshal-error": func(t *testing.T) test {
			return test{
				in:  []byte("foo"),
				err: errors.New("error unmarshaling provisioner provID into dbProvisioner"),
			}
		},
		"fail/deleted-error": func(t *testing.T) test {
			dbp := &dbProvisioner{
				DeletedAt: clock.Now(),
			}
			data, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				in:       data,
				adminErr: admin.NewError(admin.ErrorDeletedType, "provisioner %s is deleted", provID),
			}
		},
		"fail/authority-mismatch-error": func(t *testing.T) test {
			dbp := &dbProvisioner{
				ID:          provID,
				AuthorityID: "foo",
			}
			data, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				in: data,
				adminErr: admin.NewError(admin.ErrorAuthorityMismatchType,
					"provisioner %s is not owned by authority %s", provID, admin.DefaultAuthorityID),
			}
		},
		"ok": func(t *testing.T) test {
			dbp := &dbProvisioner{
				ID:          provID,
				AuthorityID: admin.DefaultAuthorityID,
				Type:        linkedca.Provisioner_JWK,
				Name:        "provName",
				CreatedAt:   clock.Now(),
			}
			data, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				in:  data,
				dbp: dbp,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			db := DB{authorityID: admin.DefaultAuthorityID}
			if dbp, err := db.unmarshalDBProvisioner(tc.in, provID); err != nil {
				switch k := err.(type) {
				case *admin.Error:
					if assert.NotNil(t, tc.adminErr) {
						assert.Equals(t, k.Type, tc.adminErr.Type)
						assert.Equals(t, k.Detail, tc.adminErr.Detail)
						assert.Equals(t, k.Status, tc.adminErr.Status)
						assert.Equals(t, k.Err.Error(), tc.adminErr.Err.Error())
						assert.Equals(t, k.Detail, tc.adminErr.Detail)
					}
				default:
					if assert.NotNil(t, tc.err) {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, dbp.ID, provID)
					assert.Equals(t, dbp.AuthorityID, tc.dbp.AuthorityID)
					assert.Equals(t, dbp.Type, tc.dbp.Type)
					assert.Equals(t, dbp.Name, tc.dbp.Name)
					assert.Equals(t, dbp.Details, tc.dbp.Details)
					assert.Equals(t, dbp.Claims, tc.dbp.Claims)
					assert.Equals(t, dbp.X509Template, tc.dbp.X509Template)
					assert.Equals(t, dbp.X509TemplateData, tc.dbp.X509TemplateData)
					assert.Equals(t, dbp.SSHTemplate, tc.dbp.SSHTemplate)
					assert.Equals(t, dbp.SSHTemplateData, tc.dbp.SSHTemplateData)
					assert.Equals(t, dbp.CreatedAt, tc.dbp.CreatedAt)
					assert.Fatal(t, dbp.DeletedAt.IsZero())
				}
			}
		})
	}
}

func defaultDBP(t *testing.T) *dbProvisioner {
	details := &linkedca.ProvisionerDetails_ACME{
		ACME: &linkedca.ACMEProvisioner{
			ForceCn: true,
		},
	}
	detailBytes, err := json.Marshal(details)
	assert.FatalError(t, err)

	return &dbProvisioner{
		ID:          "provID",
		AuthorityID: admin.DefaultAuthorityID,
		Type:        linkedca.Provisioner_ACME,
		Name:        "provName",
		Details:     detailBytes,
		Claims: &linkedca.Claims{
			DisableRenewal: true,
			X509: &linkedca.X509Claims{
				Enabled: true,
				Durations: &linkedca.Durations{
					Min:     "5m",
					Max:     "12h",
					Default: "6h",
				},
			},
			Ssh: &linkedca.SSHClaims{
				Enabled: true,
				UserDurations: &linkedca.Durations{
					Min:     "5m",
					Max:     "12h",
					Default: "6h",
				},
				HostDurations: &linkedca.Durations{
					Min:     "5m",
					Max:     "12h",
					Default: "6h",
				},
			},
		},
		X509Template:     []byte("foo"),
		X509TemplateData: []byte("bar"),
		SSHTemplate:      []byte("baz"),
		SSHTemplateData:  []byte("zap"),
		CreatedAt:        clock.Now(),
	}
}

func TestDB_unmarshalProvisioner(t *testing.T) {
	provID := "provID"
	type test struct {
		in       []byte
		err      error
		adminErr *admin.Error
		dbp      *dbProvisioner
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/unmarshal-error": func(t *testing.T) test {
			return test{
				in:  []byte("foo"),
				err: errors.New("error unmarshaling provisioner provID into dbProvisioner"),
			}
		},
		"fail/deleted-error": func(t *testing.T) test {
			dbp := &dbProvisioner{
				DeletedAt: time.Now(),
			}
			data, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				in:       data,
				adminErr: admin.NewError(admin.ErrorDeletedType, "provisioner provID is deleted"),
			}
		},
		"ok": func(t *testing.T) test {
			dbp := defaultDBP(t)
			data, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				in:  data,
				dbp: dbp,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			db := DB{authorityID: admin.DefaultAuthorityID}
			if prov, err := db.unmarshalProvisioner(tc.in, provID); err != nil {
				switch k := err.(type) {
				case *admin.Error:
					if assert.NotNil(t, tc.adminErr) {
						assert.Equals(t, k.Type, tc.adminErr.Type)
						assert.Equals(t, k.Detail, tc.adminErr.Detail)
						assert.Equals(t, k.Status, tc.adminErr.Status)
						assert.Equals(t, k.Err.Error(), tc.adminErr.Err.Error())
						assert.Equals(t, k.Detail, tc.adminErr.Detail)
					}
				default:
					if assert.NotNil(t, tc.err) {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, prov.Id, provID)
					assert.Equals(t, prov.AuthorityId, tc.dbp.AuthorityID)
					assert.Equals(t, prov.Type, tc.dbp.Type)
					assert.Equals(t, prov.Name, tc.dbp.Name)
					assert.Equals(t, prov.Claims, tc.dbp.Claims)
					assert.Equals(t, prov.X509Template, tc.dbp.X509Template)
					assert.Equals(t, prov.X509TemplateData, tc.dbp.X509TemplateData)
					assert.Equals(t, prov.SshTemplate, tc.dbp.SSHTemplate)
					assert.Equals(t, prov.SshTemplateData, tc.dbp.SSHTemplateData)

					retDetailsBytes, err := json.Marshal(prov.Details.GetData())
					assert.FatalError(t, err)
					assert.Equals(t, retDetailsBytes, tc.dbp.Details)
				}
			}
		})
	}
}

func TestDB_GetProvisioner(t *testing.T) {
	provID := "provID"
	type test struct {
		db       nosql.DB
		err      error
		adminErr *admin.Error
		dbp      *dbProvisioner
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return nil, nosqldb.ErrNotFound
					},
				},
				adminErr: admin.NewError(admin.ErrorNotFoundType, "provisioner provID not found"),
			}
		},
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading provisioner provID: force"),
			}
		},
		"fail/unmarshal-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return []byte("foo"), nil
					},
				},
				err: errors.New("error unmarshaling provisioner provID into dbProvisioner"),
			}
		},
		"fail/deleted": func(t *testing.T) test {
			dbp := defaultDBP(t)
			dbp.DeletedAt = clock.Now()
			b, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return b, nil
					},
				},
				dbp:      dbp,
				adminErr: admin.NewError(admin.ErrorDeletedType, "provisioner provID is deleted"),
			}
		},
		"fail/authorityID-mismatch": func(t *testing.T) test {
			dbp := defaultDBP(t)
			dbp.AuthorityID = "foo"
			b, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return b, nil
					},
				},
				dbp: dbp,
				adminErr: admin.NewError(admin.ErrorAuthorityMismatchType,
					"provisioner %s is not owned by authority %s", dbp.ID, admin.DefaultAuthorityID),
			}
		},
		"ok": func(t *testing.T) test {
			dbp := defaultDBP(t)
			b, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return b, nil
					},
				},
				dbp: dbp,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			db := DB{db: tc.db, authorityID: admin.DefaultAuthorityID}
			if prov, err := db.GetProvisioner(context.Background(), provID); err != nil {
				switch k := err.(type) {
				case *admin.Error:
					if assert.NotNil(t, tc.adminErr) {
						assert.Equals(t, k.Type, tc.adminErr.Type)
						assert.Equals(t, k.Detail, tc.adminErr.Detail)
						assert.Equals(t, k.Status, tc.adminErr.Status)
						assert.Equals(t, k.Err.Error(), tc.adminErr.Err.Error())
						assert.Equals(t, k.Detail, tc.adminErr.Detail)
					}
				default:
					if assert.NotNil(t, tc.err) {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, prov.Id, provID)
					assert.Equals(t, prov.AuthorityId, tc.dbp.AuthorityID)
					assert.Equals(t, prov.Type, tc.dbp.Type)
					assert.Equals(t, prov.Name, tc.dbp.Name)
					assert.Equals(t, prov.Claims, tc.dbp.Claims)
					assert.Equals(t, prov.X509Template, tc.dbp.X509Template)
					assert.Equals(t, prov.X509TemplateData, tc.dbp.X509TemplateData)
					assert.Equals(t, prov.SshTemplate, tc.dbp.SSHTemplate)
					assert.Equals(t, prov.SshTemplateData, tc.dbp.SSHTemplateData)

					retDetailsBytes, err := json.Marshal(prov.Details.GetData())
					assert.FatalError(t, err)
					assert.Equals(t, retDetailsBytes, tc.dbp.Details)
				}
			}
		})
	}
}

func TestDB_DeleteProvisioner(t *testing.T) {
	provID := "provID"
	type test struct {
		db       nosql.DB
		err      error
		adminErr *admin.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return nil, nosqldb.ErrNotFound
					},
				},
				adminErr: admin.NewError(admin.ErrorNotFoundType, "provisioner provID not found"),
			}
		},
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading provisioner provID: force"),
			}
		},
		"fail/save-error": func(t *testing.T) test {
			dbp := defaultDBP(t)
			data, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return data, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)
						assert.Equals(t, string(old), string(data))

						var _dbp = new(dbProvisioner)
						assert.FatalError(t, json.Unmarshal(nu, _dbp))

						assert.Equals(t, _dbp.ID, provID)
						assert.Equals(t, _dbp.AuthorityID, dbp.AuthorityID)
						assert.Equals(t, _dbp.Type, dbp.Type)
						assert.Equals(t, _dbp.Name, dbp.Name)
						assert.Equals(t, _dbp.Claims, dbp.Claims)
						assert.Equals(t, _dbp.X509Template, dbp.X509Template)
						assert.Equals(t, _dbp.X509TemplateData, dbp.X509TemplateData)
						assert.Equals(t, _dbp.SSHTemplate, dbp.SSHTemplate)
						assert.Equals(t, _dbp.SSHTemplateData, dbp.SSHTemplateData)
						assert.Equals(t, _dbp.CreatedAt, dbp.CreatedAt)
						assert.Equals(t, _dbp.Details, dbp.Details)

						assert.True(t, _dbp.DeletedAt.Before(time.Now()))
						assert.True(t, _dbp.DeletedAt.After(time.Now().Add(-time.Minute)))

						return nil, false, errors.New("force")
					},
				},
				err: errors.New("error saving authority provisioner: force"),
			}
		},
		"ok": func(t *testing.T) test {
			dbp := defaultDBP(t)
			data, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return data, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)
						assert.Equals(t, string(old), string(data))

						var _dbp = new(dbProvisioner)
						assert.FatalError(t, json.Unmarshal(nu, _dbp))

						assert.Equals(t, _dbp.ID, provID)
						assert.Equals(t, _dbp.AuthorityID, dbp.AuthorityID)
						assert.Equals(t, _dbp.Type, dbp.Type)
						assert.Equals(t, _dbp.Name, dbp.Name)
						assert.Equals(t, _dbp.Claims, dbp.Claims)
						assert.Equals(t, _dbp.X509Template, dbp.X509Template)
						assert.Equals(t, _dbp.X509TemplateData, dbp.X509TemplateData)
						assert.Equals(t, _dbp.SSHTemplate, dbp.SSHTemplate)
						assert.Equals(t, _dbp.SSHTemplateData, dbp.SSHTemplateData)
						assert.Equals(t, _dbp.CreatedAt, dbp.CreatedAt)
						assert.Equals(t, _dbp.Details, dbp.Details)

						assert.True(t, _dbp.DeletedAt.Before(time.Now()))
						assert.True(t, _dbp.DeletedAt.After(time.Now().Add(-time.Minute)))

						return nu, true, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			db := DB{db: tc.db, authorityID: admin.DefaultAuthorityID}
			if err := db.DeleteProvisioner(context.Background(), provID); err != nil {
				switch k := err.(type) {
				case *admin.Error:
					if assert.NotNil(t, tc.adminErr) {
						assert.Equals(t, k.Type, tc.adminErr.Type)
						assert.Equals(t, k.Detail, tc.adminErr.Detail)
						assert.Equals(t, k.Status, tc.adminErr.Status)
						assert.Equals(t, k.Err.Error(), tc.adminErr.Err.Error())
						assert.Equals(t, k.Detail, tc.adminErr.Detail)
					}
				default:
					if assert.NotNil(t, tc.err) {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
			}
		})
	}
}

/*
func TestDB_UpdateAdmin(t *testing.T) {
	provID := "provID"
	type test struct {
		db       nosql.DB
		err      error
		adminErr *admin.Error
		adm      *linkedca.Admin
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			return test{
				adm: &linkedca.Admin{Id: provID},
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return nil, nosqldb.ErrNotFound
					},
				},
				adminErr: admin.NewError(admin.ErrorNotFoundType, "provisioner provID not found"),
			}
		},
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				adm: &linkedca.Admin{Id: provID},
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading provisioner provID: force"),
			}
		},
		"fail/save-error": func(t *testing.T) test {
			dbp := &dbProvisioner{
				ID:            provID,
				AuthorityID:   admin.DefaultAuthorityID,
				ProvisionerID: "provID",
				Subject:       "max@smallstep.com",
				Type:          linkedca.Admin_SUPER_ADMIN,
				CreatedAt:     clock.Now(),
			}

			upd := dbp.convert()
			upd.Type = linkedca.Admin_ADMIN

			data, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				adm: upd,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return data, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)
						assert.Equals(t, string(old), string(data))

						var _dbp = new(dbProvisioner)
						assert.FatalError(t, json.Unmarshal(nu, _dbp))

						assert.Equals(t, _dbp.ID, dbp.ID)
						assert.Equals(t, _dbp.AuthorityID, dbp.AuthorityID)
						assert.Equals(t, _dbp.ProvisionerID, dbp.ProvisionerID)
						assert.Equals(t, _dbp.Subject, dbp.Subject)
						assert.Equals(t, _dbp.Type, linkedca.Admin_ADMIN)
						assert.Equals(t, _dbp.CreatedAt, dbp.CreatedAt)

						return nil, false, errors.New("force")
					},
				},
				err: errors.New("error saving authority provisioner: force"),
			}
		},
		"ok": func(t *testing.T) test {
			dbp := &dbProvisioner{
				ID:            provID,
				AuthorityID:   admin.DefaultAuthorityID,
				ProvisionerID: "provID",
				Subject:       "max@smallstep.com",
				Type:          linkedca.Admin_SUPER_ADMIN,
				CreatedAt:     clock.Now(),
			}

			upd := dbp.convert()
			upd.Type = linkedca.Admin_ADMIN

			data, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				adm: upd,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return data, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)
						assert.Equals(t, string(old), string(data))

						var _dbp = new(dbProvisioner)
						assert.FatalError(t, json.Unmarshal(nu, _dbp))

						assert.Equals(t, _dbp.ID, dbp.ID)
						assert.Equals(t, _dbp.AuthorityID, dbp.AuthorityID)
						assert.Equals(t, _dbp.ProvisionerID, dbp.ProvisionerID)
						assert.Equals(t, _dbp.Subject, dbp.Subject)
						assert.Equals(t, _dbp.Type, linkedca.Admin_ADMIN)
						assert.Equals(t, _dbp.CreatedAt, dbp.CreatedAt)

						return nu, true, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			db := DB{db: tc.db, authorityID: admin.DefaultAuthorityID}
			if err := db.UpdateAdmin(context.Background(), tc.adm); err != nil {
				switch k := err.(type) {
				case *admin.Error:
					if assert.NotNil(t, tc.adminErr) {
						assert.Equals(t, k.Type, tc.adminErr.Type)
						assert.Equals(t, k.Detail, tc.adminErr.Detail)
						assert.Equals(t, k.Status, tc.adminErr.Status)
						assert.Equals(t, k.Err.Error(), tc.adminErr.Err.Error())
						assert.Equals(t, k.Detail, tc.adminErr.Detail)
					}
				default:
					if assert.NotNil(t, tc.err) {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
			}
		})
	}
}

func TestDB_CreateAdmin(t *testing.T) {
	type test struct {
		db       nosql.DB
		err      error
		adminErr *admin.Error
		adm      *linkedca.Admin
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/save-error": func(t *testing.T) test {
			adm := &linkedca.Admin{
				AuthorityId:   admin.DefaultAuthorityID,
				ProvisionerId: "provID",
				Subject:       "max@smallstep.com",
				Type:          linkedca.Admin_ADMIN,
			}

			return test{
				adm: adm,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, old, nil)

						var _dbp = new(dbProvisioner)
						assert.FatalError(t, json.Unmarshal(nu, _dbp))

						assert.True(t, len(_dbp.ID) > 0 && _dbp.ID == string(key))
						assert.Equals(t, _dbp.AuthorityID, adm.AuthorityId)
						assert.Equals(t, _dbp.ProvisionerID, adm.ProvisionerId)
						assert.Equals(t, _dbp.Subject, adm.Subject)
						assert.Equals(t, _dbp.Type, linkedca.Admin_ADMIN)

						assert.True(t, _dbp.CreatedAt.Before(time.Now()))
						assert.True(t, _dbp.CreatedAt.After(time.Now().Add(-time.Minute)))

						return nil, false, errors.New("force")
					},
				},
				err: errors.New("error saving authority provisioner: force"),
			}
		},
		"ok": func(t *testing.T) test {
			adm := &linkedca.Admin{
				AuthorityId:   admin.DefaultAuthorityID,
				ProvisionerId: "provID",
				Subject:       "max@smallstep.com",
				Type:          linkedca.Admin_ADMIN,
			}

			return test{
				adm: adm,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, old, nil)

						var _dbp = new(dbProvisioner)
						assert.FatalError(t, json.Unmarshal(nu, _dbp))

						assert.True(t, len(_dbp.ID) > 0 && _dbp.ID == string(key))
						assert.Equals(t, _dbp.AuthorityID, adm.AuthorityId)
						assert.Equals(t, _dbp.ProvisionerID, adm.ProvisionerId)
						assert.Equals(t, _dbp.Subject, adm.Subject)
						assert.Equals(t, _dbp.Type, linkedca.Admin_ADMIN)

						assert.True(t, _dbp.CreatedAt.Before(time.Now()))
						assert.True(t, _dbp.CreatedAt.After(time.Now().Add(-time.Minute)))

						return nu, true, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			db := DB{db: tc.db, authorityID: admin.DefaultAuthorityID}
			if err := db.CreateAdmin(context.Background(), tc.adm); err != nil {
				switch k := err.(type) {
				case *admin.Error:
					if assert.NotNil(t, tc.adminErr) {
						assert.Equals(t, k.Type, tc.adminErr.Type)
						assert.Equals(t, k.Detail, tc.adminErr.Detail)
						assert.Equals(t, k.Status, tc.adminErr.Status)
						assert.Equals(t, k.Err.Error(), tc.adminErr.Err.Error())
						assert.Equals(t, k.Detail, tc.adminErr.Detail)
					}
				default:
					if assert.NotNil(t, tc.err) {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
			}
		})
	}
}

func TestDB_GetAdmins(t *testing.T) {
	now := clock.Now()
	fooAdmin := &dbProvisioner{
		ID:            "foo",
		AuthorityID:   admin.DefaultAuthorityID,
		ProvisionerID: "provID",
		Subject:       "foo@smallstep.com",
		Type:          linkedca.Admin_SUPER_ADMIN,
		CreatedAt:     now,
	}
	foob, err := json.Marshal(fooAdmin)
	assert.FatalError(t, err)

	barAdmin := &dbProvisioner{
		ID:            "bar",
		AuthorityID:   admin.DefaultAuthorityID,
		ProvisionerID: "provID",
		Subject:       "bar@smallstep.com",
		Type:          linkedca.Admin_ADMIN,
		CreatedAt:     now,
		DeletedAt:     now,
	}
	barb, err := json.Marshal(barAdmin)
	assert.FatalError(t, err)

	bazAdmin := &dbProvisioner{
		ID:            "baz",
		AuthorityID:   "bazzer",
		ProvisionerID: "provID",
		Subject:       "baz@smallstep.com",
		Type:          linkedca.Admin_ADMIN,
		CreatedAt:     now,
	}
	bazb, err := json.Marshal(bazAdmin)
	assert.FatalError(t, err)

	zapAdmin := &dbProvisioner{
		ID:            "zap",
		AuthorityID:   admin.DefaultAuthorityID,
		ProvisionerID: "provID",
		Subject:       "zap@smallstep.com",
		Type:          linkedca.Admin_ADMIN,
		CreatedAt:     now,
	}
	zapb, err := json.Marshal(zapAdmin)
	assert.FatalError(t, err)
	type test struct {
		db       nosql.DB
		err      error
		adminErr *admin.Error
		dbp      *dbProvisioner
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/db.List-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MList: func(bucket []byte) ([]*database.Entry, error) {
						assert.Equals(t, bucket, provisionersTable)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading admins: force"),
			}
		},
		"fail/unmarshal-error": func(t *testing.T) test {
			ret := []*database.Entry{
				{Bucket: provisionersTable, Key: []byte("foo"), Value: foob},
				{Bucket: provisionersTable, Key: []byte("bar"), Value: barb},
				{Bucket: provisionersTable, Key: []byte("zap"), Value: []byte("zap")},
			}
			return test{
				db: &db.MockNoSQLDB{
					MList: func(bucket []byte) ([]*database.Entry, error) {
						assert.Equals(t, bucket, provisionersTable)

						return ret, nil
					},
				},
				err: errors.New("error unmarshaling admin zap into dbProvisioner"),
			}
		},
		"ok": func(t *testing.T) test {
			ret := []*database.Entry{
				{Bucket: provisionersTable, Key: []byte("foo"), Value: foob},
				{Bucket: provisionersTable, Key: []byte("bar"), Value: barb},
				{Bucket: provisionersTable, Key: []byte("baz"), Value: bazb},
				{Bucket: provisionersTable, Key: []byte("zap"), Value: zapb},
			}
			return test{
				db: &db.MockNoSQLDB{
					MList: func(bucket []byte) ([]*database.Entry, error) {
						assert.Equals(t, bucket, provisionersTable)

						return ret, nil
					},
				},
				err: errors.New("error unmarshaling admin zap into dbProvisioner"),
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			db := DB{db: tc.db, authorityID: admin.DefaultAuthorityID}
			if admins, err := db.GetAdmins(context.Background()); err != nil {
				switch k := err.(type) {
				case *admin.Error:
					if assert.NotNil(t, tc.adminErr) {
						assert.Equals(t, k.Type, tc.adminErr.Type)
						assert.Equals(t, k.Detail, tc.adminErr.Detail)
						assert.Equals(t, k.Status, tc.adminErr.Status)
						assert.Equals(t, k.Err.Error(), tc.adminErr.Err.Error())
						assert.Equals(t, k.Detail, tc.adminErr.Detail)
					}
				default:
					if assert.NotNil(t, tc.err) {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
			} else {
				if assert.NotNil(t, admins) {
					assert.Equals(t, len(admins), 2)

					assert.Equals(t, admins[0].Id, fooAdmin.ID)
					assert.Equals(t, admins[0].AuthorityId, fooAdmin.AuthorityID)
					assert.Equals(t, admins[0].ProvisionerId, fooAdmin.ProvisionerID)
					assert.Equals(t, admins[0].Subject, fooAdmin.Subject)
					assert.Equals(t, admins[0].Type, fooAdmin.Type)

					assert.Equals(t, admins[1].Id, zapAdmin.ID)
					assert.Equals(t, admins[1].AuthorityId, zapAdmin.AuthorityID)
					assert.Equals(t, admins[1].ProvisionerId, zapAdmin.ProvisionerID)
					assert.Equals(t, admins[1].Subject, zapAdmin.Subject)
					assert.Equals(t, admins[1].Type, zapAdmin.Type)
				}
			}
		})
	}
}
*/
