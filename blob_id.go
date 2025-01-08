package minileap

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

var (
	ErrInvalidBlobID      = fmt.Errorf("Invalid blob ID")
	ErrInvalidNoncePrefix = fmt.Errorf("Invalid nonce prefix")
)

type BlobID [32]byte

func (blobID BlobID) String() string {
	return fmt.Sprintf("%x", blobID[:])
}

// Thank you ChatGPT

// MarshalJSON implements the json.Marshaler interface.
// This method allows BlobID to be marshaled into a hexadecimal string.
func (b BlobID) MarshalJSON() ([]byte, error) {
	// Convert the BlobID bytes to a hexadecimal string.
	hexString := hex.EncodeToString(b[:])

	// json.Marshal needs a string in quotes to be valid JSON string,
	// hence the use of strconv.Quote.
	return json.Marshal(hexString)
}

// UnmarshalJSON implements the json.Unmarshaler interface.
// This method allows BlobID to be unmarshaled from a hexadecimal string.
func (b *BlobID) UnmarshalJSON(data []byte) error {
	// Unmarshal the data into a string.
	var hexString string
	if err := json.Unmarshal(data, &hexString); err != nil {
		return err
	}

	// Decode the hexadecimal string back to bytes.
	decodedBytes, err := hex.DecodeString(hexString)
	if err != nil {
		return err
	}

	// Ensure the decoded bytes fit into the BlobID byte array.
	if len(decodedBytes) != len(b) {
		return fmt.Errorf("hex string length does not match BlobID length")
	}

	copy(b[:], decodedBytes)
	return nil
}

func NewBlob() (noncePrefix [18]byte, blobID BlobID, err error) {
	nonce, err := RandomNonce()
	if err != nil {
		return
	}

	noncePrefix = [18]byte((*nonce)[:18])
	blobID = BlobID(blake2b.Sum256(noncePrefix[:]))

	return noncePrefix, blobID, nil
}

func ValidNoncePrefix(noncePrefix []byte) error {
	noncePrefixLength := len(noncePrefix)

	if noncePrefixLength != 0 && noncePrefixLength != 12 && noncePrefixLength != 18 {
		return fmt.Errorf("Nonce prefix length == %v: %w", noncePrefixLength,
			ErrInvalidNoncePrefix)
	}

	return nil
}
