package model

import "github.com/jinzhu/gorm"

// ErrRecordNotFound : localize "record not found" to model package.
var ErrRecordNotFound error = gorm.ErrRecordNotFound
