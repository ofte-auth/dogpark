package db

import "github.com/ofte-auth/dogpark/internal/util"

// QueryStatement creates a default query and count statement from APIParams.
func QueryStatement(db DB, tableName string, params *util.APIParams, apiToDBFieldMap map[string]string) (DB, DB, error) {
	if params == nil {
		params = util.DefaultAPIParams()
	}
	for k, v := range params.AndFilters {
		if fieldName, ok := apiToDBFieldMap[k]; ok {
			delete(params.AndFilters, k)
			params.AndFilters[fieldName] = v
		}
	}
	db = db.New().Table(tableName)
	if params.Deep {
		db = db.Set("gorm:auto_preload", true)
	}
	if !params.CreatedBefore.IsZero() {
		db = db.Where("created_at < ?", params.CreatedBefore)
	}
	if !params.CreatedAfter.IsZero() {
		db = db.Where("created_at > ?", params.CreatedAfter)
	}
	db = db.Where(params.AndFilters)
	countDB := db

	db = db.Limit(params.Limit).Offset(params.GetOffsetSQL())
	orderStatement := params.GetOrderBySQLStatement(apiToDBFieldMap)
	if orderStatement != "" {
		db = db.Order(orderStatement)
	}
	db = db.Where(params.AndFilters)

	return db, countDB, nil
}
