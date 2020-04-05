package service

import (
	"context"

	"github.com/ofte-auth/dogpark/internal/model"
	"github.com/ofte-auth/dogpark/internal/util"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// Admin defines the admin service interface.
type Admin interface {
	Principal(context.Context, string) (*model.Principal, error)
	AddPrincipal(context.Context, map[string]string) (*model.Principal, error)
	UpdatePrincipal(context.Context, string, map[string]string) (*model.Principal, string, error)
	PrincipalByUsername(context.Context, string) (*model.Principal, error)
	Principals(context.Context, *util.APIParams) ([]*model.Principal, int64, error)

	FIDOKey(context.Context, string) (*model.FIDOKey, error)
	UpdateFIDOKey(context.Context, string, map[string]string) (*model.FIDOKey, string, error)
	DeleteFIDOKey(context.Context, string) error
	FIDOKeys(context.Context, *util.APIParams) ([]*model.FIDOKey, int64, error)

	AAGUID(context.Context, string) (*model.AAGUID, error)
	AddAAGUID(context.Context, map[string]string) (*model.AAGUID, error)
	UpdateAAGUID(context.Context, string, map[string]string) (*model.AAGUID, string, error)
	AAGUIDs(context.Context, *util.APIParams) ([]*model.AAGUID, int64, error)
	AAGUIDWhitelist(context.Context) (util.StringSet, error)
	AAGUIDBlacklist(context.Context) (util.StringSet, error)

	Session(context.Context, string) (*model.Session, error)
	Sessions(context.Context, *util.APIParams) ([]*model.Session, int64, error)
	KillSession(context.Context, string) (*model.Session, error)

	LogByID(context.Context, int64) (*model.AuditEntry, error)
	Logs(context.Context, *util.APIParams) ([]*model.AuditEntry, int64, error)

	Stop()
}

type adminService struct {
	Service
}

// NewAdminService ...
func NewAdminService(ctx context.Context, options ...func(*Service) error) (Admin, error) {
	service := &adminService{
		Service: Service{
			name: "dogpark-admin-service",
		},
	}
	for _, option := range options {
		err := option(&(service).Service)
		if err != nil {
			return nil, err
		}
	}
	if service.db == nil {
		return nil, errors.New("db member is nil")
	}
	if service.kv == nil {
		return nil, errors.New("kv member is nil")
	}
	if _, ok := service.params["fido_mds_token"]; !ok {
		log.Warning("fido_mds_token not found, see https://fidoalliance.org/metadata/")
	}
	return service, nil
}

func (s *adminService) Stop() {
	s.Service.Stop()
}

func (s *adminService) AddPrincipal(ctx context.Context, params map[string]string) (*model.Principal, error) {
	var (
		p   *model.Principal
		err error
	)
	// Auditing
	defer func() {
		go s.Audit(ctx, "admin", "addPrincipal", p, nil, err)
	}()

	p = model.NewPrincipal(params["id"], params["username"], model.StateActive, params["displayName"], params["icon"])
	err = s.db.Create(p).Error
	if err != nil {
		err = errors.Wrap(err, "Adding principal")
		return nil, err
	}

	return p, nil
}

func (s *adminService) UpdatePrincipal(ctx context.Context, id string, values map[string]string) (*model.Principal, string, error) {
	var (
		p   *model.Principal
		err error
	)
	// Auditing
	defer func() {
		go s.Audit(ctx, "admin", "updatePrincipal", p, nil, err)
	}()

	p, err = model.PrincipalByID(ctx, s.db, id, true)
	if err != nil {
		return nil, "", err
	}
	diff, err := p.ApplyChanges(values)
	if err != nil {
		return nil, diff, err
	}
	err = s.db.Save(p).Error

	return p, diff, err
}

func (s *adminService) Principal(ctx context.Context, id string) (*model.Principal, error) {
	p, err := model.PrincipalByID(ctx, s.db, id, true)
	// Auditing
	defer func() {
		go s.Audit(ctx, "admin", "getPrincipalByID", p, nil, err)
	}()
	return p, err
}

func (s *adminService) PrincipalByUsername(ctx context.Context, username string) (*model.Principal, error) {
	p, err := model.PrincipalByUsername(ctx, s.db, username, true)
	// Auditing
	defer func() {
		go s.Audit(ctx, "admin", "getPrincipalByUsername", p, nil, err)
	}()

	return p, err
}

func (s *adminService) Principals(ctx context.Context, params *util.APIParams) ([]*model.Principal, int64, error) {
	principals, count, err := model.Principals(ctx, s.db, params)
	// Auditing
	defer func() {
		go s.Audit(ctx, "admin", "listPrincipals", nil, nil, err)
	}()

	return principals, count, err
}

func (s *adminService) FIDOKey(ctx context.Context, id string) (*model.FIDOKey, error) {
	fidoKey, err := model.FIDOKeyByID(ctx, s.db, id)
	// Auditing
	defer func() {
		go s.Audit(ctx, "admin", "getFIDOKey", nil, fidoKey, err)
	}()
	return fidoKey, err
}

func (s *adminService) UpdateFIDOKey(ctx context.Context, id string, values map[string]string) (*model.FIDOKey, string, error) {
	var diff string
	k, err := model.FIDOKeyByID(ctx, s.db, id)
	// Auditing
	defer func() {
		go s.Audit(ctx, "admin", "updateFIDOKey", nil, k, err)
	}()

	if err != nil {
		return nil, diff, err
	}
	diff, err = k.ApplyChanges(values)
	if err != nil {
		return nil, diff, err
	}
	err = s.db.Save(k).Error

	return k, diff, err
}

func (s *adminService) DeleteFIDOKey(ctx context.Context, id string) error {
	k, err := model.FIDOKeyByID(ctx, s.db, id)
	// Auditing
	defer func() {
		go s.Audit(ctx, "admin", "deleteFIDOKey", nil, k, err)
	}()
	if err != nil {
		return err
	}
	err = s.db.Delete(k).Error

	return err
}

func (s *adminService) FIDOKeys(ctx context.Context, params *util.APIParams) ([]*model.FIDOKey, int64, error) {
	keys, count, err := model.FIDOKeys(ctx, s.db, params)
	// Auditing
	defer func() {
		go s.Audit(ctx, "admin", "listFIDOKeys", nil, nil, err)
	}()

	return keys, count, err
}

func (s *adminService) AAGUID(ctx context.Context, id string) (*model.AAGUID, error) {
	aaguid, err := model.AAGUIDByID(ctx, s.db, id)
	// Auditing
	defer func() {
		go s.Audit(ctx, "admin", "getAAGUID", nil, &model.FIDOKey{AAGUID: id}, err)
	}()

	return aaguid, err
}

func (s *adminService) AddAAGUID(ctx context.Context, params map[string]string) (*model.AAGUID, error) {
	var (
		id  string
		err error
	)
	id, ok := params["id"]
	if !ok {
		return nil, errors.New("id not in params")
	}
	guid := &model.AAGUID{
		ID:    id,
		Label: params["label"],
		State: params["state"],
	}
	// Auditing
	defer func() {
		go s.Audit(ctx, "admin", "addAAGUID", nil, &model.FIDOKey{AAGUID: id}, err)
	}()

	err = s.db.Create(guid).Error
	if err != nil {
		return nil, errors.Wrap(err, "adding AAGUID")
	}

	if _, ok := s.params["fido_mds_token"]; ok {
		go func() {
			_ = UpdateFIDOMetadata(s.db, id, s.params["fido_mds_token"])
		}()
	}
	return guid, nil
}

func (s *adminService) UpdateAAGUID(ctx context.Context, id string, values map[string]string) (*model.AAGUID, string, error) {
	var diff string
	aaguid, err := model.AAGUIDByID(ctx, s.db, id)
	if err != nil {
		return nil, diff, err
	}
	// Auditing
	defer func() {
		go s.Audit(ctx, "admin", "updateAAGUID", nil, &model.FIDOKey{AAGUID: id}, err)
	}()
	diff, err = aaguid.ApplyChanges(values)
	if err != nil {
		return nil, diff, err
	}
	err = s.db.Save(aaguid).Error

	return aaguid, diff, err
}

func (s *adminService) AAGUIDs(ctx context.Context, params *util.APIParams) ([]*model.AAGUID, int64, error) {
	list, count, err := model.AAGUIDs(ctx, s.db, params)
	// Auditing
	defer func() {
		go s.Audit(ctx, "admin", "listAAGUIDs", nil, nil, err)
	}()

	return list, count, err
}

func (s *adminService) AAGUIDWhitelist(ctx context.Context) (util.StringSet, error) {
	set, err := model.WhitelistAAGUIDs(ctx, s.db)
	// Auditing
	defer func() {
		go s.Audit(ctx, "admin", "getAAGUIDsWhitelist", nil, nil, err)
	}()

	return set, err
}

func (s *adminService) AAGUIDBlacklist(ctx context.Context) (util.StringSet, error) {
	set, err := model.BlacklistAAGUIDs(ctx, s.db)
	// Auditing
	defer func() {
		go s.Audit(ctx, "admin", "getAAGUIDsBlacklist", nil, nil, err)
	}()

	return set, err
}

func (s *adminService) Session(ctx context.Context, id string) (*model.Session, error) {
	session, err := model.SessionByID(ctx, s.kv, id)
	defer func() {
		go s.Audit(ctx, "admin", "getSession", nil, nil, err)
	}()

	return session, err
}

func (s *adminService) Sessions(ctx context.Context, params *util.APIParams) ([]*model.Session, int64, error) {
	sessions, count, err := model.Sessions(ctx, s.kv, params)
	defer func() {
		go s.Audit(ctx, "admin", "listSessions", nil, nil, err)
	}()

	return sessions, count, err
}

func (s *adminService) KillSession(ctx context.Context, id string) (*model.Session, error) {
	var (
		err     error
		session *model.Session
	)
	defer func() {
		p := &model.Principal{}
		if session != nil {
			p.ID = session.PrincipalID
			p.Username = session.PrincipalUsername
		}
		go s.Audit(ctx, "admin", "killSession", p, nil, err)
	}()
	session, err = model.SessionByID(ctx, s.kv, id)
	if err != nil {
		return nil, err
	}
	session.State = model.StateRevoked
	err = session.Put(ctx, s.kv, model.SessionTTL)
	return session, err
}

func (s *adminService) LogByID(ctx context.Context, id int64) (*model.AuditEntry, error) {
	return model.AuditEntryByID(s.db, id)
}

func (s *adminService) Logs(ctx context.Context, params *util.APIParams) ([]*model.AuditEntry, int64, error) {
	list, count, err := model.AuditEntries(ctx, s.db, params)
	defer func() {
		go s.Audit(ctx, "admin", "listLogs", nil, nil, err)
	}()

	return list, count, err
}
