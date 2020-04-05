package http

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/ofte-auth/dogpark/internal/db"
	"github.com/ofte-auth/dogpark/internal/geo"
	"github.com/ofte-auth/dogpark/internal/service"
	"github.com/ofte-auth/dogpark/internal/store"
	"github.com/ofte-auth/dogpark/internal/util"
	log "github.com/sirupsen/logrus"
)

// Handler is a base http-handling object.
type Handler struct {
	name               string
	router             *chi.Mux
	db                 db.DB
	kv                 store.Manager
	geo                geo.Resolver
	ipAddress          string
	httpPort           int
	tlsCertificateFile string
	tlsPrivateKeyFile  string
	options            map[string]string
}

// OptionDB applies a db connection option.
func OptionDB(db db.DB) func(*Handler) error {
	return func(handler *Handler) error {
		handler.db = db
		return nil
	}
}

// OptionKV applies a key value manager option.
func OptionKV(kv store.Manager) func(*Handler) error {
	return func(handler *Handler) error {
		handler.kv = kv
		return nil
	}
}

// OptionIPAddress applies a IP address option.
func OptionIPAddress(ipAddress string) func(*Handler) error {
	return func(handler *Handler) error {
		handler.ipAddress = ipAddress
		return nil
	}
}

// OptionHTTPPort applies a TCP port option, used by the http handler.
func OptionHTTPPort(port int) func(*Handler) error {
	return func(handler *Handler) error {
		handler.httpPort = port
		return nil
	}
}

// OptionGeoResolver applies a geo resolver option.
func OptionGeoResolver(geo geo.Resolver) func(*Handler) error {
	return func(handler *Handler) error {
		handler.geo = geo
		return nil
	}
}

// OptionTLS applies TLS parameters, used by the http handler.
func OptionTLS(certFile, keyFile string) func(*Handler) error {
	return func(handler *Handler) error {
		if certFile == "" && keyFile == "" {
			return nil
		}
		handler.tlsCertificateFile = certFile
		handler.tlsPrivateKeyFile = keyFile
		return nil
	}
}

// OptionParams applies a name,value option, more than one can be added.
func OptionParams(key, value string) func(*Handler) error {
	return func(handler *Handler) error {
		if handler.options == nil {
			handler.options = make(map[string]string)
		}
		handler.options[key] = value
		return nil
	}
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(200)
	_, _ = w.Write([]byte("ok"))
}

// Start commences http handling.
func (handler *Handler) Start() error {
	handler.router.Get("/healthz", healthz)

	address := fmt.Sprintf("%s:%d", handler.ipAddress, handler.httpPort)
	if handler.tlsCertificateFile == "" {
		log.WithFields(log.Fields{
			"service": handler.name,
			"port":    handler.httpPort,
		}).Info("Starting http handler")
		return http.ListenAndServe(address, handler.router)
	}
	log.WithFields(log.Fields{
		"service": handler.name,
		"port":    handler.httpPort,
	}).Info("Starting https handler")
	return http.ListenAndServeTLS(address, handler.tlsCertificateFile, handler.tlsPrivateKeyFile, handler.router)
}

// ClientContext is http middleware that adds a request's ip address and
// user agent to the context.
func ClientContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ipAddr := util.ClientIP(r)
		ctx := context.WithValue(r.Context(), service.ContextIPAddr, ipAddr)
		ctx = context.WithValue(ctx, service.ContextUserAgent, r.UserAgent())
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
