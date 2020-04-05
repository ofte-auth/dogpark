package util

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
)

const (
	limit          = "limit"
	page           = "page"
	orderBy        = "orderBy"
	orderDirection = "orderDirection"
	createdBefore  = "createdBefore"
	createdAfter   = "createdAfter"
	since          = "since"
	deep           = "deep"
)

// APIParams represents common API parameters.
type APIParams struct {
	Ordering       []string
	OrderDirection string
	AndFilters     map[string]interface{}
	Limit          int64
	Page           int64
	CreatedBefore  time.Time
	CreatedAfter   time.Time
	Deep           bool
}

// NewAPIParams constructs a params object from an `http.Request`. If the optional allowed params set
// is passed, arguments are checked against those.
func NewAPIParams(request *http.Request, allowed StringSet) (*APIParams, error) {
	var (
		err   error
		found bool
		value []string
	)
	params := &APIParams{
		Page:       1,
		Limit:      20,
		AndFilters: make(map[string]interface{}),
	}
	values := request.URL.Query()
	if value, found = values[limit]; found {
		delete(values, limit)
		params.Limit, err = strconv.ParseInt(value[0], 10, 0)
		if err != nil {
			return nil, errors.Wrap(err, "converting limit argument to integer")
		}
	}
	if value, found = values[page]; found {
		delete(values, page)
		params.Page, err = strconv.ParseInt(value[0], 10, 0)
		if err != nil {
			return nil, errors.Wrap(err, "converting page argument to integer")
		}
	}
	if value, found = values[orderBy]; found {
		delete(values, orderBy)
		params.Ordering = value
	}
	if value, found = values[orderDirection]; found {
		delete(values, orderDirection)
		direction := strings.ToLower(value[0])
		if strings.Index(direction, "desc") == 0 {
			params.OrderDirection = "DESC"
		}
	}

	parse := func(t string) (time.Time, error) {
		timestamp, err := time.Parse(time.RFC3339, t)
		if err != nil {
			timestamp, err = time.Parse("2006-01-02", t)
		}
		return timestamp, err
	}
	if value, found = values[createdBefore]; found {
		delete(values, createdBefore)
		params.CreatedBefore, err = parse(value[0])
		if err != nil {
			return nil, errors.Errorf("invalid time parameter %s, should be in RFC3339 or shortened (2006-06-24) format", value[0])
		}
	}
	if value, found = values[createdAfter]; found {
		delete(values, createdAfter)
		params.CreatedAfter, err = parse(value[0])
		if err != nil {
			return nil, errors.Errorf("invalid time parameter %s, should be in RFC3339 or shortened (2006-06-24) format", value[0])
		}
	}
	if !params.CreatedAfter.IsZero() && params.CreatedAfter.Before(params.CreatedBefore) {
		return nil, errors.New("createdAfter cannot be prior to createdBefore")
	}
	if value, found = values[since]; found {
		delete(values, since)
		duration, err := time.ParseDuration(value[0])
		if err != nil {
			return nil, errors.Errorf("invalid duration parameter %s", value[0])
		}
		params.CreatedAfter = time.Now().Add(-duration)
	}
	if value, found := values[deep]; found {
		delete(values, deep)
		params.Deep = (strings.ToLower(value[0]) == "true")
	}

	for k, v := range values {
		if allowed != nil {
			if _, found = allowed[k]; !found {
				return nil, errors.Errorf("invalid parameter %s", k)
			}
		}
		params.AndFilters[k] = v[0]
	}
	return params, nil
}

// DefaultAPIParams returns default APIParams.
func DefaultAPIParams() *APIParams {
	return &APIParams{
		Page:       1,
		Limit:      20,
		AndFilters: make(map[string]interface{}),
	}
}

// GetOrderBySQLStatement returns an SQL statement for ordering.
func (params *APIParams) GetOrderBySQLStatement(fieldMap map[string]string) string {
	var statement strings.Builder
	for n, v := range params.Ordering {
		field := v
		if alias, ok := fieldMap[field]; ok {
			field = alias
		}
		statement.WriteString(fmt.Sprintf("%s %s", field, params.OrderDirection))
		if n < len(params.Ordering)-1 {
			statement.WriteString(",")
		}
	}
	return statement.String()
}

// GetOffsetSQL calculates the SQL offset from the page and limit parameters.
func (params *APIParams) GetOffsetSQL() int64 {
	if params.Limit == 0 {
		return -1
	}
	return (params.Page - 1) * params.Limit
}

// Constants for HTTP headers to support pagination.
const (
	ResultsPage  = "Results-Page"
	ResultsLimit = "Results-Limit"
	ResultsTotal = "Results-Total"
)

// WritePaginationHeaders adds pagination headers to a http response writer.
func (params *APIParams) WritePaginationHeaders(w http.ResponseWriter, total int64) {
	w.Header().Set(ResultsPage, fmt.Sprintf("%d", params.Page))
	w.Header().Set(ResultsLimit, fmt.Sprintf("%d", params.Limit))
	w.Header().Set(ResultsTotal, fmt.Sprintf("%d", total))
}
