package util

import "github.com/go-playground/validator/v10"

// Validate exposes the validator in the util package.
var Validate *validator.Validate

func init() {
	Validate = validator.New()
}
