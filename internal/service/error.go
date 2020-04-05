package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ofte-auth/dogpark/internal/util"
	log "github.com/sirupsen/logrus"
	"github.com/ztrue/tracerr"
)

// APIError defines a API error.
type APIError struct {
	Code   int    `json:"code"`
	Err    error  `json:"error"`
	Detail string `json:"detail,omitempty"`
}

// NewAPIError returns a new API error. If `source` is true, source code is also written to stdout.
func NewAPIError(code int, err error, detail string) *APIError {
	apiError := &APIError{
		Code:   code,
		Err:    err,
		Detail: detail,
	}
	if code >= 500 {
		apiError.Err = tracerr.Wrap(err)
	}
	return apiError
}

func (e *APIError) Error() string {
	return e.Err.Error()
}

// BindHTTPRequest binds an API error to a HTTP Request's context.
func (e *APIError) BindHTTPRequest(r *http.Request) {
	ctx := context.WithValue(r.Context(), ContextError, e)
	*r = *r.Clone(ctx)
}

// MarshalJSON ...
func (e *APIError) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Code   int    `json:"code"`
		Error  string `json:"error"`
		Detail string `json:"detail,omitempty"`
	}{
		Code:   e.Code,
		Error:  e.Err.Error(),
		Detail: e.Detail,
	})
}

// ErrorHandler is middleware to log and process HTTP errors.
func ErrorHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		err := r.Context().Value(ContextError)
		if err == nil {
			return
		}
		switch err := err.(type) {
		case *APIError:
			log.WithField("error", err).Error(err)
			util.JSONResponse(w, err, err.Code)
			if err, ok := err.Err.(tracerr.Error); ok {
				fmt.Println(err)
				frames := err.StackTrace()
				for _, v := range frames[1:4] {
					fmt.Println(v)
				}
				fmt.Println("<snip>")
			}
		case error:
			log.WithField("error", err).Error(err)
			http.Error(w, err.(error).Error(), 500)
		}
	})
}
