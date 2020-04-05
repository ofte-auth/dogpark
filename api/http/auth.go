package http

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/cors"
	"github.com/ofte-auth/dogpark/api/model"
	"github.com/ofte-auth/dogpark/internal"
	"github.com/ofte-auth/dogpark/internal/service"
	"github.com/ofte-auth/dogpark/internal/util"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	config "github.com/spf13/viper"
	"go.uber.org/multierr"
)

// AuthHandler implements the Auth REST API.
type AuthHandler struct {
	Handler

	service service.Auth
}

// NewAuthHandler creates a new Auth API endpoint.
func NewAuthHandler(ctx context.Context, options ...func(*Handler) error) (*AuthHandler, error) {
	var err error
	handler := &AuthHandler{
		Handler: Handler{
			name: "auth-http-handler",
		},
	}

	for _, option := range options {
		err := option(&(handler).Handler)
		if err != nil {
			return nil, err
		}
	}

	handler.service, err = service.NewAuthService(ctx,
		service.OptionDB(handler.db),
		service.OptionKV(handler.kv),
		service.OptionRP(handler.options["rpDisplayName"], handler.options["rpID"], handler.options["rpOrigin"]),
		service.OptionGeoResolver(handler.geo),
	)
	if err != nil {
		return nil, err
	}
	return handler, nil
}

// Init sets up the Dogpark HTTP handlers for FIDO registration and authorization.
// Note that there is no first factor authn/z employed here.
//
// Suggestions:
// - restrict the `cors_allowed_origins` to your webapp in which first factor authn is occuring
// - add your own authz middleware that checks authn header for valid session (and add to client)
func (handler *AuthHandler) Init() {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(ClientContext)

	allowedOrigins := config.GetStringSlice("cors_allowed_origins")
	for _, v := range allowedOrigins {
		if v == "*" {
			log.Warning("cors_allowed_origins configured without restriction (*)")
		}
	}

	cors := cors.New(cors.Options{
		AllowedOrigins: allowedOrigins,
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "Ofte-SessionID", "Ofte-AccessToken"},
		ExposedHeaders: []string{"Link", "Ofte-AccessToken"},
		MaxAge:         300,
	})
	r.Use(cors.Handler)
	r.Use(service.ErrorHandler)

	r.Route("/auth/v1", func(r chi.Router) {

		r.Get("/version", handler.getVersion)
		r.Post("/principals", handler.getOrCreatePrincipal)

		r.Get("/start_fido_registration/{username}", handler.startFIDORegistration)
		r.Post("/finish_fido_registration/{username}", handler.finishFIDORegistration)
		r.Get("/start_fido_login/{username}", handler.startFIDOLogin)
		r.Post("/finish_fido_login/{username}", handler.finishFIDOLogin)
	})

	handler.router = r
}

// Stop ...
func (handler *AuthHandler) Stop() error {
	handler.service.Stop()
	return nil
}

func (handler *AuthHandler) getVersion(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte(internal.Version()))
	w.WriteHeader(200)
}

func (handler *AuthHandler) getOrCreatePrincipal(w http.ResponseWriter, r *http.Request) {
	var (
		params map[string]string
	)
	val := util.Validate.Var
	body, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "reading request body"), "").BindHTTPRequest(r)
		return
	}
	ctx := r.Context()
	now := time.Now()
	err = json.Unmarshal(body, &params)
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "unmarshalling request body"), "").BindHTTPRequest(r)
		return
	}
	err = val(params["username"], "required")
	err = multierr.Append(err, val(params["displayName"], "required"))
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "required parameters missing"), "").BindHTTPRequest(r)
		return
	}
	p, apiError := handler.service.GetOrCreatePrincipal(ctx, params)
	if apiError != nil {
		apiError.BindHTTPRequest(r)
		return
	}
	code := 200
	if p.CreatedAt.After(now) {
		code = 201
	}
	util.JSONResponse(w, p, code)
}

func (handler *AuthHandler) startFIDORegistration(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	if username == "" {
		service.NewAPIError(400, errors.New("username required"), "starting FIDO registration").BindHTTPRequest(r)
		return
	}
	options, err := handler.service.StartFIDORegistration(r.Context(), username)
	if err != nil {
		err.BindHTTPRequest(r)
		return
	}
	util.JSONResponse(w, options, 200)
}

func (handler *AuthHandler) finishFIDORegistration(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	if username == "" {
		service.NewAPIError(400, errors.New("username required"), "finishing FIDO registration").BindHTTPRequest(r)
		return
	}
	a11r, err := handler.service.FinishFIDORegistration(r.Context(), username, r)
	if err != nil {
		err.BindHTTPRequest(r)
		return
	}
	util.JSONResponse(w, a11r, 200)
}

func (handler *AuthHandler) startFIDOLogin(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	if username == "" {
		service.NewAPIError(400, errors.New("username required"), "starting FIDO login").BindHTTPRequest(r)
		return
	}
	assert, err := handler.service.StartFIDOLogin(r.Context(), username)
	if err != nil {
		err.BindHTTPRequest(r)
		return
	}
	util.JSONResponse(w, assert, 200)
}

func (handler *AuthHandler) finishFIDOLogin(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	if username == "" {
		service.NewAPIError(400, errors.New("username required"), "starting FIDO login").BindHTTPRequest(r)
		return
	}
	res, err := handler.service.FinishFIDOLogin(r.Context(), username, r)
	if err != nil {
		err.BindHTTPRequest(r)
		return
	}
	p := &model.Principal{
		ID:       res.ID,
		Username: res.Username,
		Icon:     res.Icon,
	}
	util.JSONResponse(w, p, 200)
}
