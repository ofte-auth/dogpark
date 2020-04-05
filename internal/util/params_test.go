package util

import (
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewAPIParams(t *testing.T) {
	s := "https://foo.bar.com:5432/path?foo=bar&bar=foo1&bar=foo2&limit=10&page=2&orderBy=date&orderDirection=descending"
	u, err := url.Parse(s)
	assert.NoError(t, err)

	request := &http.Request{}
	request.URL = u

	p, err := NewAPIParams(request, nil)
	assert.NoError(t, err)
	assert.True(t, reflect.DeepEqual(p, &APIParams{
		Ordering:       []string{"date"},
		OrderDirection: "DESC",
		Limit:          10,
		Page:           2,
		AndFilters: map[string]interface{}{
			"bar": "foo1",
			"foo": "bar",
		},
	}))

	_, err = NewAPIParams(request, NewStringSet("param1"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid parameter")
}
