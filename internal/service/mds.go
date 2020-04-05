package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/ofte-auth/dogpark/internal/db"
	"github.com/ofte-auth/dogpark/internal/model"
	"github.com/ofte-auth/dogpark/internal/util"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"go.uber.org/multierr"
)

type mdsResult struct {
	AAGUID      string `json:"aaguid"`
	Description string `json:"description"`
}

// UpdateFIDOMetadata pulls metadata from the FIDO Alliance Metadata Service
// and associates it with the AAGUID (`id`).
func UpdateFIDOMetadata(db db.DB, id, mdsToken string) error {
	val := util.Validate.Var
	err := val(id, "required,uuid")
	err = multierr.Append(err, val(mdsToken, "required,alphanum"))
	if err != nil {
		log.WithError(err).Error("Error validating function arguments")
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()
	url := fmt.Sprintf("https://mds2.fidoalliance.org/metadata/%s?token=%s", id, mdsToken)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		log.WithError(err).WithField("url", url).Warning("Error creating MDS url")
		return err
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.WithError(err).WithField("url", url).Warning("Error querying MDS url")
		return err
	}
	if resp.StatusCode != 200 {
		log.WithField("url", url).WithField("status", resp.StatusCode).Warning("Non 200 result from MDS query")
		return errors.New("Non 200 result from MDS query")
	}
	data, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		log.WithError(err).WithField("url", url).Warning("Error reading MDS result")
		return err
	}
	b, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		log.WithError(err).Warning("Error decoding MDS result")
		return err
	}
	aaguid, err := model.AAGUIDByID(ctx, db, id)
	switch err {
	case model.ErrRecordNotFound:
		result := &mdsResult{}
		err = json.Unmarshal(b, &result)
		if err != nil {
			log.WithError(err).Warning("Error parsing MDS result for description")
			return err
		}
		if result.AAGUID != id {
			log.Warning("GUID mismatch from MDS, not storing record")
			return errors.New("GUID mismatch from MDS, not storing record")
		}
		aaguid = &model.AAGUID{
			ID:       id,
			State:    "",
			Label:    result.Description,
			Metadata: b,
		}
		err = db.Create(aaguid).Error
	case nil:
		aaguid.Metadata = b
		err = db.Save(aaguid).Error
	default:
		// unexpected error with DB
	}
	if err != nil {
		log.WithError(err).WithField("url", url).Warning("Error managing AAGUID data")
	}
	return err
}
