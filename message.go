package minileap

import (
	"time"

	log "github.com/sirupsen/logrus"
)

type Message struct {
	FromAccountID string    `json:"from_account_id"`
	ToAccountID   string    `json:"to_account_id"`
	Created       time.Time `json:"created"`
	FromMe        bool      `json:"from_me"`

	// These fields are in common with `EncryptionConfig`
	BlobID        BlobID `json:"blob_id"`
	MsgType       uint16 `json:"msg_type"`
	OrigFilename  string `json:"orig_filename"`
	SavedLocation string `json:"saved_location"`

	Text string `json:"text"`
}

func (msg *Message) SavedAs() string {
	if msg == nil {
		log.Errorf("(*minileap.Message is nil)")
		return ""
	}
	if msg.SavedLocation != "" {
		return msg.SavedLocation
	}
	return msg.OrigFilename
}
