package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3gen"
	"github.com/ghodss/yaml"
	"github.com/ofte-auth/dogpark/internal/model"
)

// Used to generate openapi yaml file for components.
func main() {
	components := openapi3.NewComponents()
	components.Schemas = make(map[string]*openapi3.SchemaRef)

	key, _, err := openapi3gen.NewSchemaRefForValue(&model.FIDOKey{})
	if err != nil {
		panic(err)
	}
	components.Schemas["v1.Key"] = key

	principal, _, err := openapi3gen.NewSchemaRefForValue(&model.Principal{})
	if err != nil {
		panic(err)
	}
	components.Schemas["v1.Principal"] = principal

	aaguid, _, err := openapi3gen.NewSchemaRefForValue(&model.AAGUID{})
	if err != nil {
		panic(err)
	}
	components.Schemas["v1.AAGUID"] = aaguid

	log, _, err := openapi3gen.NewSchemaRefForValue(&model.AuditEntry{})
	if err != nil {
		panic(err)
	}
	components.Schemas["v1.Log"] = log

	b := &bytes.Buffer{}
	err = json.NewEncoder(b).Encode(components.Schemas)
	if err != nil {
		panic(err)
	}

	y, err := yaml.JSONToYAML(b.Bytes())
	if err != nil {
		panic(err)
	}

	err = ioutil.WriteFile("cmd/spec/schemas.yaml", y, 0644)
	if err != nil {
		panic(err)
	}
	fmt.Println("wrote schemas.yaml")
}
