package ca

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"reflect"
	"sync"

	"github.com/go-chi/chi"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	acmeAPI "github.com/smallstep/certificates/acme/api"
	acmeNoSQL "github.com/smallstep/certificates/acme/db/nosql"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority"
	adminAPI "github.com/smallstep/certificates/authority/admin/api"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/logging"
	"github.com/smallstep/certificates/monitoring"
	"github.com/smallstep/certificates/scep"
	scepAPI "github.com/smallstep/certificates/scep/api"
	"github.com/smallstep/certificates/server"
	"github.com/smallstep/nosql"
)

type options struct {
	configFile     string
	password       []byte
	issuerPassword []byte
	database       db.AuthDB
}

func (o *options) apply(opts []Option) {
	for _, fn := range opts {
		fn(o)
	}
}

// Option is the type of options passed to the CA constructor.
type Option func(o *options)

// WithConfigFile sets the given name as the configuration file name in the CA
// options.
func WithConfigFile(name string) Option {
	return func(o *options) {
		o.configFile = name
	}
}

// WithPassword sets the given password as the configured password in the CA
// options.
func WithPassword(password []byte) Option {
	return func(o *options) {
		o.password = password
	}
}

// WithIssuerPassword sets the given password as the configured certificate
// issuer password in the CA options.
func WithIssuerPassword(password []byte) Option {
	return func(o *options) {
		o.issuerPassword = password
	}
}

// WithDatabase sets the given authority database to the CA options.
func WithDatabase(db db.AuthDB) Option {
	return func(o *options) {
		o.database = db
	}
}

// CA is the type used to build the complete certificate authority. It builds
// the HTTP server, set ups the middlewares and the HTTP handlers.
type CA struct {
	auth        *authority.Authority
	config      *config.Config
	srv         *server.Server
	insecureSrv *server.Server
	opts        *options
	renewer     *TLSRenewer
}

// New creates and initializes the CA with the given configuration and options.
func New(config *config.Config, opts ...Option) (*CA, error) {
	ca := &CA{
		config: config,
		opts:   new(options),
	}
	ca.opts.apply(opts)
	return ca.Init(config)
}

// Init initializes the CA with the given configuration.
func (ca *CA) Init(config *config.Config) (*CA, error) {
	// Intermediate Password.
	if len(ca.opts.password) > 0 {
		ca.config.Password = string(ca.opts.password)
	}

	// Certificate issuer password for RA mode.
	if len(ca.opts.issuerPassword) > 0 {
		if ca.config.AuthorityConfig != nil && ca.config.AuthorityConfig.CertificateIssuer != nil {
			ca.config.AuthorityConfig.CertificateIssuer.Password = string(ca.opts.issuerPassword)
		}
	}

	var opts []authority.Option
	if ca.opts.database != nil {
		opts = append(opts, authority.WithDatabase(ca.opts.database))
	}

	auth, err := authority.New(config, opts...)
	if err != nil {
		return nil, err
	}
	ca.auth = auth

	tlsConfig, err := ca.getTLSConfig(auth)
	if err != nil {
		return nil, err
	}

	// Using chi as the main router
	mux := chi.NewRouter()
	handler := http.Handler(mux)

	insecureMux := chi.NewRouter()
	insecureHandler := http.Handler(insecureMux)

	// Add regular CA api endpoints in / and /1.0
	routerHandler := api.New(auth)
	routerHandler.Route(mux)
	mux.Route("/1.0", func(r chi.Router) {
		routerHandler.Route(r)
	})

	//Add ACME api endpoints in /acme and /1.0/acme
	dns := config.DNSNames[0]
	u, err := url.Parse("https://" + config.Address)
	if err != nil {
		return nil, err
	}
	port := u.Port()
	if port != "" && port != "443" {
		dns = fmt.Sprintf("%s:%s", dns, port)
	}

	// ACME Router
	prefix := "acme"
	var acmeDB acme.DB
	if config.DB == nil {
		acmeDB = nil
	} else {
		acmeDB, err = acmeNoSQL.New(auth.GetDatabase().(nosql.DB))
		if err != nil {
			return nil, errors.Wrap(err, "error configuring ACME DB interface")
		}
	}
	acmeHandler := acmeAPI.NewHandler(acmeAPI.HandlerOptions{
		Backdate: *config.AuthorityConfig.Backdate,
		DB:       acmeDB,
		DNS:      dns,
		Prefix:   prefix,
		CA:       auth,
	})
	mux.Route("/"+prefix, func(r chi.Router) {
		acmeHandler.Route(r)
	})
	// Use 2.0 because, at the moment, our ACME api is only compatible with v2.0
	// of the ACME spec.
	mux.Route("/2.0/"+prefix, func(r chi.Router) {
		acmeHandler.Route(r)
	})

	// Admin API Router
	if config.AuthorityConfig.EnableAdmin {
		adminDB := auth.GetAdminDatabase()
		if adminDB != nil {
			adminHandler := adminAPI.NewHandler(auth)
			mux.Route("/admin", func(r chi.Router) {
				adminHandler.Route(r)
			})
		}
	}

	if ca.shouldServeSCEPEndpoints() {
		scepPrefix := "scep"
		scepAuthority, err := scep.New(auth, scep.AuthorityOptions{
			Service: auth.GetSCEPService(),
			DNS:     dns,
			Prefix:  scepPrefix,
		})
		if err != nil {
			return nil, errors.Wrap(err, "error creating SCEP authority")
		}
		scepRouterHandler := scepAPI.New(scepAuthority)

		// According to the RFC (https://tools.ietf.org/html/rfc8894#section-7.10),
		// SCEP operations are performed using HTTP, so that's why the API is mounted
		// to the insecure mux.
		insecureMux.Route("/"+scepPrefix, func(r chi.Router) {
			scepRouterHandler.Route(r)
		})

		// The RFC also mentions usage of HTTPS, but seems to advise
		// against it, because of potential interoperability issues.
		// Currently I think it's not bad to use HTTPS also, so that's
		// why I've kept the API endpoints in both muxes and both HTTP
		// as well as HTTPS can be used to request certificates
		// using SCEP.
		mux.Route("/"+scepPrefix, func(r chi.Router) {
			scepRouterHandler.Route(r)
		})
	}

	// helpful routine for logging all routes
	//dumpRoutes(mux)

	// Add monitoring if configured
	if len(config.Monitoring) > 0 {
		m, err := monitoring.New(config.Monitoring)
		if err != nil {
			return nil, err
		}
		handler = m.Middleware(handler)
	}

	// Add logger if configured
	if len(config.Logger) > 0 {
		logger, err := logging.New("ca", config.Logger)
		if err != nil {
			return nil, err
		}
		handler = logger.Middleware(handler)
	}

	ca.srv = server.New(config.Address, handler, tlsConfig)

	// only start the insecure server if the insecure address is configured
	// and, currently, also only when it should serve SCEP endpoints.
	if ca.shouldServeSCEPEndpoints() && config.InsecureAddress != "" {
		// TODO: instead opt for having a single server.Server but two
		// http.Servers handling the HTTP and HTTPS handler? The latter
		// will probably introduce more complexity in terms of graceful
		// reload.
		ca.insecureSrv = server.New(config.InsecureAddress, insecureHandler, nil)
	}

	return ca, nil
}

// Run starts the CA calling to the server ListenAndServe method.
func (ca *CA) Run() error {
	var wg sync.WaitGroup
	errors := make(chan error, 1)

	if ca.insecureSrv != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errors <- ca.insecureSrv.ListenAndServe()
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		errors <- ca.srv.ListenAndServe()
	}()

	// wait till error occurs; ensures the servers keep listening
	err := <-errors

	wg.Wait()

	return err
}

// Stop stops the CA calling to the server Shutdown method.
func (ca *CA) Stop() error {
	ca.renewer.Stop()
	if err := ca.auth.Shutdown(); err != nil {
		log.Printf("error stopping ca.Authority: %+v\n", err)
	}
	return ca.srv.Shutdown()
}

// Reload reloads the configuration of the CA and calls to the server Reload
// method.
func (ca *CA) Reload() error {
	config, err := config.LoadConfiguration(ca.opts.configFile)
	if err != nil {
		return errors.Wrap(err, "error reloading ca configuration")
	}

	logContinue := func(reason string) {
		log.Println(reason)
		log.Println("Continuing to run with the original configuration.")
		log.Println("You can force a restart by sending a SIGTERM signal and then restarting the step-ca.")
	}

	// Do not allow reload if the database configuration has changed.
	if !reflect.DeepEqual(ca.config.DB, config.DB) {
		logContinue("Reload failed because the database configuration has changed.")
		return errors.New("error reloading ca: database configuration cannot change")
	}

	newCA, err := New(config,
		WithPassword(ca.opts.password),
		WithIssuerPassword(ca.opts.issuerPassword),
		WithConfigFile(ca.opts.configFile),
		WithDatabase(ca.auth.GetDatabase()),
	)
	if err != nil {
		logContinue("Reload failed because the CA with new configuration could not be initialized.")
		return errors.Wrap(err, "error reloading ca")
	}

	if err = ca.srv.Reload(newCA.srv); err != nil {
		logContinue("Reload failed because server could not be replaced.")
		return errors.Wrap(err, "error reloading server")
	}

	// 1. Stop previous renewer
	// 2. Safely shutdown any internal resources (e.g. key manager)
	// 3. Replace ca properties
	// Do not replace ca.srv
	ca.renewer.Stop()
	ca.auth.CloseForReload()
	ca.auth = newCA.auth
	ca.config = newCA.config
	ca.opts = newCA.opts
	ca.renewer = newCA.renewer
	return nil
}

// getTLSConfig returns a TLSConfig for the CA server with a self-renewing
// server certificate.
func (ca *CA) getTLSConfig(auth *authority.Authority) (*tls.Config, error) {
	// Create initial TLS certificate
	tlsCrt, err := auth.GetTLSCertificate()
	if err != nil {
		return nil, err
	}

	// Start tls renewer with the new certificate.
	// If a renewer was started, attempt to stop it before.
	if ca.renewer != nil {
		ca.renewer.Stop()
	}

	ca.renewer, err = NewTLSRenewer(tlsCrt, auth.GetTLSCertificate)
	if err != nil {
		return nil, err
	}
	ca.renewer.Run()

	var tlsConfig *tls.Config
	if ca.config.TLS != nil {
		tlsConfig = ca.config.TLS.TLSConfig()
	} else {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	certPool := x509.NewCertPool()
	for _, crt := range auth.GetRootCertificates() {
		certPool.AddCert(crt)
	}

	// GetCertificate will only be called if the client supplies SNI
	// information or if tlsConfig.Certificates is empty.
	// When client requests are made using an IP address (as opposed to a domain
	// name) the server does not receive any SNI and may fallback to using the
	// first entry in the Certificates attribute; by setting the attribute to
	// empty we are implicitly forcing GetCertificate to be the only mechanism
	// by which the server can find it's own leaf Certificate.
	tlsConfig.Certificates = []tls.Certificate{}
	tlsConfig.GetCertificate = ca.renewer.GetCertificateForCA

	// Add support for mutual tls to renew certificates
	tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
	tlsConfig.ClientCAs = certPool

	// Use server's most preferred ciphersuite
	tlsConfig.PreferServerCipherSuites = true

	return tlsConfig, nil
}

// shouldMountSCEPEndpoints returns if the CA should be
// configured with endpoints for SCEP. This is assumed to be
// true if a SCEPService exists, which is true in case a
// SCEP provisioner was configured.
func (ca *CA) shouldServeSCEPEndpoints() bool {
	return ca.auth.GetSCEPService() != nil
}

//nolint // ignore linters to allow keeping this function around for debugging
func dumpRoutes(mux chi.Routes) {
	// helpful routine for logging all routes //
	walkFunc := func(method string, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		fmt.Printf("%s %s\n", method, route)
		return nil
	}
	if err := chi.Walk(mux, walkFunc); err != nil {
		fmt.Printf("Logging err: %s\n", err.Error())
	}
}
