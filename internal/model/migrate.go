package model

import (
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

// Migrate ...
func Migrate(db *gorm.DB) error {

	if db == nil {
		return errors.New("db cannot be nil")
	}

	// Principals
	err := db.AutoMigrate(&Principal{}).Error
	if err != nil {
		return err
	}

	// Keys
	err = db.AutoMigrate(&FIDOKey{}).Error
	if err != nil {
		return err
	}
	err = db.Model(&FIDOKey{}).AddForeignKey("principal_id", "principals(id)", "CASCADE", "CASCADE").Error
	if err != nil {
		return err
	}
	err = db.AutoMigrate(&CAKey{}).Error
	if err != nil {
		return err
	}
	err = db.Model(&CAKey{}).AddForeignKey("fidokey_id", "fido_keys(id)", "CASCADE", "CASCADE").Error
	if err != nil {
		return err
	}

	// AAGUIDs
	err = db.AutoMigrate(&AAGUID{}).Error
	if err != nil {
		return err
	}

	// AuditEntries
	err = db.AutoMigrate(&AuditEntry{}).Error
	if err != nil {
		return err
	}

	// Principals KeyCount View
	err = db.Exec(principalsKeyCountStatement).Error
	if err != nil {
		return err
	}

	return nil
}

const principalsKeyCountStatement = `
	CREATE OR REPLACE VIEW principals_keycount AS 
	SELECT principals.*, count(fido_keys.id) as number_of_keys        
	from principals
	LEFT join fido_keys
	on (principals.id = fido_keys.principal_id)
	group by
		principals.id
`
