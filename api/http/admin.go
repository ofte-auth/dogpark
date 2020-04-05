package http

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/cors"
	apimodel "github.com/ofte-auth/dogpark/api/model"
	"github.com/ofte-auth/dogpark/internal"
	"github.com/ofte-auth/dogpark/internal/model"
	"github.com/ofte-auth/dogpark/internal/service"
	"github.com/ofte-auth/dogpark/internal/store"
	"github.com/ofte-auth/dogpark/internal/util"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	config "github.com/spf13/viper"
)

// AdminHandler implements the Admin REST API.
type AdminHandler struct {
	Handler

	service service.Admin
}

// NewAdminHandler creates a new Admin API endpoint.
func NewAdminHandler(ctx context.Context, options ...func(*Handler) error) (*AdminHandler, error) {
	var err error
	handler := &AdminHandler{
		Handler: Handler{
			name: "admin-http-handler",
		},
	}
	for _, option := range options {
		err := option(&(handler).Handler)
		if err != nil {
			return nil, err
		}
	}
	handler.service, err = service.NewAdminService(ctx,
		service.OptionDB(handler.db),
		service.OptionKV(handler.kv),
		service.OptionGeoResolver(handler.geo),
		service.OptionParams(handler.options),
	)
	if err != nil {
		return nil, err
	}
	return handler, nil
}

// Init ...
func (handler *AdminHandler) Init() {

	// TODO: add in support for your authn/z mechanism for these endpoints
	// (and then delete the line following)
	log.Warning("Service running without authorization in place")

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
		AllowedHeaders: []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders: []string{"Link", "Results-Page", "Results-Limit", "Results-Total"},
		MaxAge:         300,
	})
	r.Use(cors.Handler)
	r.Use(service.ErrorHandler)

	r.Route("/admin/v1", func(r chi.Router) {

		r.Get("/version", handler.getVersion)

		r.Group(func(r chi.Router) {
			r.Route("/principals", func(r chi.Router) {
				r.Get("/", handler.listPrincipals)
				r.Post("/", handler.addPrincipal)
				r.Get("/{principalID}", handler.getPrincipal)
				r.Put("/{principalID}", handler.updatePrincipal)
			})
		})

		r.Group(func(r chi.Router) {
			r.Route("/keys", func(r chi.Router) {
				r.Get("/", handler.listKeys)
				r.Get("/{keyID}", handler.getKey)
				r.Put("/{keyID}", handler.updateKey)
				r.Delete("/{keyID}", handler.deleteKey)
			})
		})

		r.Group(func(r chi.Router) {
			r.Route("/aaguids", func(r chi.Router) {
				r.Get("/", handler.listAAGUIDs)
				r.Post("/", handler.createAAGUID)
				r.Get("/{aaguid}", handler.getAAGUID)
				r.Put("/{aaguid}", handler.updateAAGUID)
				r.Get("/whitelist", handler.aaguidWhitelist)
				r.Get("/blacklist", handler.aaguidBlacklist)
			})
		})

		r.Group(func(r chi.Router) {
			r.Route("/sessions", func(r chi.Router) {
				r.Get("/", handler.sessions)
				r.Get("/{sessionID}", handler.getSession)
				r.Delete("/{sessionID}", handler.killSession)
			})
		})

		r.Group(func(r chi.Router) {
			r.Route("/logs", func(r chi.Router) {
				r.Get("/", handler.listLogs)
				r.Get("/{id}", handler.getLog)
			})
		})
	})

	handler.router = r
}

func (handler *AdminHandler) getVersion(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte(internal.Version()))
	w.WriteHeader(200)
}

// Stop ...
func (handler *AdminHandler) Stop() error {
	handler.service.Stop()
	return nil
}

var baseParams = util.NewStringSet("limit", "page", "orderBy", "orderDirection", "createdBefore", "createdAfter", "since")

var adminParamRestrictions = map[string]util.StringSet{
	"listPrincipals": baseParams.Copy().Add("state").Add("deep").Add("hasKeys"),
	"listKeys":       baseParams.Copy().Add("state"),
	"listAAGUIDs":    baseParams.Copy().Add("state"),
	"listSessions":   baseParams.Copy().Add("state"),
	"listLogs":       baseParams.Copy().Add("group").Add("action").Add("isAnomaly").Add("principalId").Add("principalUsername").Add("keyId").Add("sessionId").Add("ipAddr"),
}

func (handler *AdminHandler) listPrincipals(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	apiParams, err := util.NewAPIParams(r, adminParamRestrictions["listPrincipals"])
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "parsing params"), "").BindHTTPRequest(r)
		return
	}
	list, count, err := handler.service.Principals(ctx, apiParams)
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "getting principals"), err.Error()).BindHTTPRequest(r)
		return
	}
	apiParams.WritePaginationHeaders(w, count)
	util.JSONResponse(w, list, 200)
}

func (handler *AdminHandler) getPrincipal(w http.ResponseWriter, r *http.Request) {
	var (
		p   *model.Principal
		err error
	)
	ctx := r.Context()
	id := chi.URLParam(r, "principalID")
	if id == "" {
		service.NewAPIError(400, errors.New("principal ID required"), "").BindHTTPRequest(r)
		return
	}

	p, err = handler.service.Principal(ctx, id)
	if err == model.ErrRecordNotFound {
		p, err = handler.service.PrincipalByUsername(ctx, id)
	}
	switch err {
	case nil:
		util.JSONResponse(w, p, 200)
	case model.ErrRecordNotFound:
		service.NewAPIError(404, errors.New("principal not found"), "").BindHTTPRequest(r)
		return
	default:
		service.NewAPIError(500, errors.Wrap(err, "getting principal"), "").BindHTTPRequest(r)
		return
	}
}

func (handler *AdminHandler) addPrincipal(w http.ResponseWriter, r *http.Request) {
	var p *model.Principal
	ctx := r.Context()

	var values map[string]string
	body, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "reading request body"), "").BindHTTPRequest(r)
		return
	}
	err = json.Unmarshal(body, &values)
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "unmarshalling request body"), "").BindHTTPRequest(r)
		return
	}
	p, err = handler.service.AddPrincipal(ctx, values)
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "adding principal"), "").BindHTTPRequest(r)
		return
	}
	util.JSONResponse(w, p, 201)
}

func (handler *AdminHandler) updatePrincipal(w http.ResponseWriter, r *http.Request) {
	var p *model.Principal
	ctx := r.Context()
	id := chi.URLParam(r, "principalID")
	if id == "" {
		service.NewAPIError(400, errors.New("principal ID required"), "").BindHTTPRequest(r)
		return
	}

	p, err := handler.service.Principal(ctx, id)
	if err == model.ErrRecordNotFound {
		p, err = handler.service.PrincipalByUsername(ctx, id)
	}
	switch err {
	case nil:
		// do nothing
	case model.ErrRecordNotFound:
		service.NewAPIError(404, errors.New("principal not found"), "").BindHTTPRequest(r)
		return
	default:
		service.NewAPIError(400, errors.Wrap(err, "getting principal"), "").BindHTTPRequest(r)
		return
	}
	var values map[string]string
	body, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "reading request body"), "").BindHTTPRequest(r)
		return
	}
	err = json.Unmarshal(body, &values)
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "unmarshalling request body"), "").BindHTTPRequest(r)
		return
	}
	p, _, err = handler.service.UpdatePrincipal(ctx, p.ID, values)
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "updating principal"), "").BindHTTPRequest(r)
		return
	}
	util.JSONResponse(w, p, 200)
}

func (handler *AdminHandler) listKeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	apiParams, err := util.NewAPIParams(r, adminParamRestrictions["listKeys"])
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "parsing params"), "").BindHTTPRequest(r)
		return
	}
	list, count, err := handler.service.FIDOKeys(ctx, apiParams)
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "getting fidokeys"), "").BindHTTPRequest(r)
		return
	}
	apiParams.WritePaginationHeaders(w, count)

	util.JSONResponse(w, list, 200)
}

func (handler *AdminHandler) getKey(w http.ResponseWriter, r *http.Request) {
	var (
		k   *model.FIDOKey
		err error
	)
	ctx := r.Context()
	id := chi.URLParam(r, "keyID")
	if id == "" {
		service.NewAPIError(400, errors.New("key ID required"), "").BindHTTPRequest(r)
		return
	}
	k, err = handler.service.FIDOKey(ctx, id)
	switch err {
	case nil:
		util.JSONResponse(w, k, 200)
	case model.ErrRecordNotFound:
		service.NewAPIError(404, errors.New("key not found"), "").BindHTTPRequest(r)
		return
	default:
		service.NewAPIError(500, errors.Wrap(err, "getting key"), "").BindHTTPRequest(r)
		return
	}
}

func (handler *AdminHandler) updateKey(w http.ResponseWriter, r *http.Request) {
	var (
		k   *model.FIDOKey
		err error
	)
	ctx := r.Context()
	id := chi.URLParam(r, "keyID")
	if id == "" {
		service.NewAPIError(400, errors.New("authenticator ID required"), "").BindHTTPRequest(r)
		return
	}
	k, err = handler.service.FIDOKey(ctx, id)
	switch err {
	case nil:
		// do nothing
	case model.ErrRecordNotFound:
		service.NewAPIError(404, errors.New("key not found"), "").BindHTTPRequest(r)
		return
	default:
		service.NewAPIError(400, errors.Wrap(err, "getting key"), "").BindHTTPRequest(r)
		return
	}
	var values map[string]string
	body, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "reading request body"), "").BindHTTPRequest(r)
		return
	}
	err = json.Unmarshal(body, &values)
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "unmarshalling request body"), "").BindHTTPRequest(r)
		return
	}
	k, _, err = handler.service.UpdateFIDOKey(ctx, k.ID, values)
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "updating authenticator"), "").BindHTTPRequest(r)
		return
	}
	util.JSONResponse(w, k, 200)
}

func (handler *AdminHandler) deleteKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "keyID")
	if id == "" {
		service.NewAPIError(400, errors.New("key ID required"), "").BindHTTPRequest(r)
		return
	}
	err := handler.service.DeleteFIDOKey(ctx, id)
	switch err {
	case nil:
		w.WriteHeader(204)
	case model.ErrRecordNotFound:
		service.NewAPIError(404, errors.New("key not found"), "").BindHTTPRequest(r)
		return
	default:
		service.NewAPIError(400, errors.Wrap(err, "getting key"), "").BindHTTPRequest(r)
		return
	}
}

func (handler *AdminHandler) createAAGUID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var values map[string]string
	body, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "reading request body"), "").BindHTTPRequest(r)
		return
	}
	err = json.Unmarshal(body, &values)
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "unmarshalling request body"), "").BindHTTPRequest(r)
		return
	}
	aaguid, err := handler.service.AddAAGUID(ctx, values)
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "adding AAGUID"), "").BindHTTPRequest(r)
		return
	}
	util.JSONResponse(w, aaguid, 201)
}

func (handler *AdminHandler) getAAGUID(w http.ResponseWriter, r *http.Request) {
	var (
		aaguid *model.AAGUID
		err    error
	)
	ctx := r.Context()
	id := chi.URLParam(r, "aaguid")
	if id == "" {
		service.NewAPIError(400, errors.New("aaguid required"), "").BindHTTPRequest(r)
		return
	}
	aaguid, err = handler.service.AAGUID(ctx, id)
	switch err {
	case nil:
		util.JSONResponse(w, aaguid, 200)
	case model.ErrRecordNotFound:
		service.NewAPIError(404, errors.New("aaguid not found"), "").BindHTTPRequest(r)
		return
	default:
		service.NewAPIError(400, errors.Wrap(err, "getting aaguid"), "").BindHTTPRequest(r)
		return
	}
}

func (handler *AdminHandler) updateAAGUID(w http.ResponseWriter, r *http.Request) {
	var (
		aaguid *model.AAGUID
		err    error
	)
	ctx := r.Context()
	id := chi.URLParam(r, "aaguid")
	if id == "" {
		service.NewAPIError(400, errors.New("aaguid parameter required"), "").BindHTTPRequest(r)
		return
	}
	aaguid, err = handler.service.AAGUID(ctx, id)
	switch err {
	case nil:
		// do nothing
	case model.ErrRecordNotFound:
		service.NewAPIError(404, errors.New("aaguid not found"), "").BindHTTPRequest(r)
		return
	default:
		service.NewAPIError(400, errors.Wrap(err, "getting key"), "").BindHTTPRequest(r)
		return
	}
	var values map[string]string
	body, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "reading request body"), "").BindHTTPRequest(r)
		return
	}
	err = json.Unmarshal(body, &values)
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "unmarshalling request body"), "").BindHTTPRequest(r)
		return
	}
	aaguid, _, err = handler.service.UpdateAAGUID(ctx, aaguid.ID, values)
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "updating aaguid"), "").BindHTTPRequest(r)
		return
	}
	util.JSONResponse(w, aaguid, 200)
}

func (handler *AdminHandler) listAAGUIDs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	apiParams, err := util.NewAPIParams(r, adminParamRestrictions["listAAGUIDs"])
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "parsing params"), "").BindHTTPRequest(r)
		return
	}
	resp, count, err := handler.service.AAGUIDs(ctx, apiParams)
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "getting aaguids"), "").BindHTTPRequest(r)
		return
	}
	apiParams.WritePaginationHeaders(w, count)
	util.JSONResponse(w, resp, 200)
}

func (handler *AdminHandler) aaguidWhitelist(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	resp, err := handler.service.AAGUIDWhitelist(ctx)
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "getting aaguid whitelist"), "").BindHTTPRequest(r)
		return
	}
	util.JSONResponse(w, resp.Values(), 200)
}

func (handler *AdminHandler) aaguidBlacklist(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	resp, err := handler.service.AAGUIDBlacklist(ctx)
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "getting aaguid blacklist"), "").BindHTTPRequest(r)
		return
	}
	util.JSONResponse(w, resp.Values(), 200)
}

func (handler *AdminHandler) sessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	apiParams, err := util.NewAPIParams(r, adminParamRestrictions["listSessions"])
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "parsing params"), "").BindHTTPRequest(r)
		return
	}
	resp, count, err := handler.service.Sessions(ctx, apiParams)
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "getting sessions"), "").BindHTTPRequest(r)
		return
	}
	apiParams.WritePaginationHeaders(w, count)
	list := []*apimodel.Session{}
	for _, v := range resp {
		entry, err := handler.geo.Resolve(v.IPAddr)
		if err != nil {
			log.Errorln(err)
			continue
		}
		entry.UserAgent = v.UserAgent
		entry.Timestamp = v.UpdatedAt
		list = append(list, &apimodel.Session{
			GeoEntry:  *entry,
			SessionID: v.ID,
			State:     v.State,
			FIDOKeyID: v.FIDOKeyID,
			AAGUID:    v.AAGUID,
			UserID:    v.PrincipalID,
			Username:  v.PrincipalUsername,
			Age:       time.Since(v.CreatedAt).Truncate(time.Second).String(),
		})
	}
	util.JSONResponse(w, list, 200)
}

func (handler *AdminHandler) getSession(w http.ResponseWriter, r *http.Request) {
	var (
		session *model.Session
		err     error
	)
	ctx := r.Context()
	id := chi.URLParam(r, "sessionID")
	if id == "" {
		service.NewAPIError(400, errors.New("session ID required"), "").BindHTTPRequest(r)
		return
	}
	session, err = handler.service.Session(ctx, id)
	switch err {
	case nil:
		util.JSONResponse(w, session, 200)
	case store.ErrorNoRecord:
		service.NewAPIError(404, errors.New("session not found"), "").BindHTTPRequest(r)
		return
	default:
		service.NewAPIError(400, errors.Wrap(err, "getting session"), "").BindHTTPRequest(r)
		return
	}
}

func (handler *AdminHandler) killSession(w http.ResponseWriter, r *http.Request) {
	var (
		err     error
		session *model.Session
	)
	ctx := r.Context()
	id := chi.URLParam(r, "sessionID")
	if id == "" {
		service.NewAPIError(400, errors.New("session ID required"), "").BindHTTPRequest(r)
		return
	}
	session, err = handler.service.KillSession(ctx, id)
	switch err {
	case nil:
		util.JSONResponse(w, session, 200)
	case store.ErrorNoRecord:
		service.NewAPIError(404, errors.New("session not found"), "").BindHTTPRequest(r)
		return
	default:
		service.NewAPIError(400, errors.Wrap(err, "revoking session"), "").BindHTTPRequest(r)
		return
	}
}

func (handler *AdminHandler) getLog(w http.ResponseWriter, r *http.Request) {
	var (
		err   error
		entry *model.AuditEntry
	)
	ctx := r.Context()
	id := chi.URLParam(r, "id")
	err = util.Validate.Var(id, "required,numeric,gt=0")
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "parsing id parameter"), err.Error()).BindHTTPRequest(r)
		return
	}
	entryID, _ := strconv.ParseInt(id, 10, 64)

	entry, err = handler.service.LogByID(ctx, entryID)
	switch err {
	case nil:
		util.JSONResponse(w, entry, 200)
	case store.ErrorNoRecord:
		service.NewAPIError(404, errors.New("entry not found"), "").BindHTTPRequest(r)
		return
	default:
		service.NewAPIError(400, errors.Wrap(err, "getting entry"), "").BindHTTPRequest(r)
		return
	}
}

func (handler *AdminHandler) listLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	apiParams, err := util.NewAPIParams(r, adminParamRestrictions["listLogs"])
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "parsing params"), "").BindHTTPRequest(r)
		return
	}
	list, count, err := handler.service.Logs(ctx, apiParams)
	if err != nil {
		service.NewAPIError(400, errors.Wrap(err, "getting log entries"), "").BindHTTPRequest(r)
		return
	}
	apiParams.WritePaginationHeaders(w, count)

	util.JSONResponse(w, list, 200)
}
