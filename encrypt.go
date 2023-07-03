package minileap

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cathalgarvey/base58"
	"github.com/cryptag/go-minilock/taber"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/ssh/terminal"
)

func init() {
	if os.Getenv("DEBUG") == "1" {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.FatalLevel)
	}
}

const (
	NonceLength = 24
	// EncryptChunkLength tells us how big a chunk should be encrypted
	// at once.
	EncryptChunkLength = 100_000

	Blake2bHashLength = blake2b.Size

	// 104 == 24 + 16 + 64. Does not include IsLastChunkIndicatorLength.
	NonceCryptoBlakeOverhead = NonceLength + secretbox.Overhead + Blake2bHashLength

	// 2-byte message type (big endian)
	EncryptHeaderLength = 2

	DecryptHeaderLength = EncryptHeaderLength + NonceCryptoBlakeOverhead

	IsLastChunkIndicatorLength = 1

	// Use DecryptChunkLength when decrypting
	DecryptChunkOverhead = IsLastChunkIndicatorLength + NonceCryptoBlakeOverhead

	ValidKeyLength = 32

	MiniLeapFileExtension             = "minileap"
	MiniLeapFileExtensionIncludingDot = "." + MiniLeapFileExtension

	EncryptFilenameChunkLength = 256
)

const (
	MaxMsgType = uint16(1<<16 - 1) // 65,535

	MinFilenameLength = 1
	MaxFilenameLength = 255

	//
	// Message types
	//
	MessageTypeInvalid                 = uint16(0)
	MessageTypeText                    = uint16(1)
	MessageTypeURL                     = uint16(2)
	MessageTypeCommand                 = uint16(3)
	MessageTypePassphrase              = uint16(4)
	MessageTypeFileWithFilename        = uint16(5)
	MessageTypeFileWithFilenameAndPath = uint16(6)
)

var empty32ByteArray = [32]byte{}

func MessageTypeName(msgType uint16) string {
	switch msgType {
	case MessageTypeInvalid:
		return fmt.Sprintf("MessageTypeInvalid (number %v)", msgType)
	case MessageTypeText:
		return fmt.Sprintf("MessageTypeText (number %v)", msgType)
	case MessageTypeURL:
		return fmt.Sprintf("MessageTypeURL (number %v)", msgType)
	case MessageTypeCommand:
		return fmt.Sprintf("MessageTypeCommand (number %v)", msgType)
	case MessageTypePassphrase:
		return fmt.Sprintf("MessageTypePassphrase (number %v)", msgType)
	case MessageTypeFileWithFilename:
		return fmt.Sprintf("MessageTypeFileWithFilename (number %v)", msgType)
	case MessageTypeFileWithFilenameAndPath:
		return fmt.Sprintf("MessageTypeFileWithFilenameAndPath (number %v)", msgType)
	}
	return fmt.Sprintf("Unknown (number %v)", msgType)
}

var (
	ErrInvalidNonce          = fmt.Errorf("Invalid nonce")
	ErrInvalidKey            = fmt.Errorf("Invalid key")
	ErrInvalidKeyLength      = fmt.Errorf("Invalid key length")
	ErrInvalidChunkLength    = fmt.Errorf("Header: invalid chunk length")
	ErrInvalidMessageType    = fmt.Errorf("Header: invalid message type")
	ErrChunkDecryptionFailed = fmt.Errorf("Chunk decryption failed")
	ErrInvalidChunkHash      = fmt.Errorf("Invalid chunk hash")
	ErrInvalidFinalHash      = fmt.Errorf("Invalid final hash")
	ErrInvalidEncryptConfig  = fmt.Errorf("Invalid encryption configuration options")
	ErrInvalidFilenameLength = fmt.Errorf("Invalid filename length")
	ErrInvalidAccountID      = fmt.Errorf("Invalid account ID; must be valid base58 and of length 33 after being decoded")

	// Don't let an attacker who's sending me a file control which
	// directory it ends up in
	InvalidFilenameChars = []string{`/`, `\`}

	TestKey = &[ValidKeyLength]byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1,
	}
)

type EncryptionConfig struct {
	OrigFilename  string
	MsgType       uint16
	Blake         hash.Hash
	PlainFile     io.Writer
	SavedLocation string
}

func (config *EncryptionConfig) SavedAs() string {
	if config == nil {
		return "(*EncryptionConfig is nil)"
	}
	if config.SavedLocation != "" {
		return config.SavedLocation
	}
	return config.OrigFilename
}

func EncryptFile(plainFilename string, key *[32]byte, dest string, forceOverwrite bool) (cipherFilename string, err error) {
	if key == nil || *key == empty32ByteArray {
		return "", ErrInvalidKey
	}

	basePlainFilename := filepath.Base(plainFilename)

	for _, char := range InvalidFilenameChars {
		if strings.Contains(basePlainFilename, char) {
			return "", fmt.Errorf("Filename `%s` contains invalid character `%s`!",
				basePlainFilename, char)
		}
	}

	if dest == "" {
		// Save encrypted file with ".minileap" extension appended
		cipherFilename = plainFilename + MiniLeapFileExtensionIncludingDot
	} else if exists, err := DirExists(dest); exists && err != nil {
		cipherFilename = filepath.Clean(dest) + string(filepath.Separator) + basePlainFilename + MiniLeapFileExtensionIncludingDot
	} else {
		cipherFilename = dest
	}

	exists, err := FileExists(cipherFilename)
	if err != nil {
		return "", err
	}

	if exists && !forceOverwrite {
		return cipherFilename, fmt.Errorf("Encrypted file `%s` already exists and you've chosen not to overwrite existing files!", cipherFilename)
	}

	plainFile, err := os.Open(plainFilename)
	if err != nil {
		return cipherFilename, err
	}
	defer plainFile.Close()

	cipherFile, err := os.Create(cipherFilename)
	if err != nil {
		return cipherFilename, err
	}
	defer cipherFile.Close()

	encConfig := &EncryptionConfig{
		OrigFilename: filepath.Base(plainFilename),
		MsgType:      MessageTypeFileWithFilename,
	}

	err = EncryptReaderToWriter(MessageTypeFileWithFilename, plainFile, key, cipherFile, encConfig)
	if err != nil {
		return cipherFilename, err
	}

	return cipherFilename, nil
}

func EncryptReaderToWriter(msgType uint16, plainFile io.Reader, key *[32]byte, cipherFile io.Writer, encConfig *EncryptionConfig) error {
	if key == nil || *key == empty32ByteArray {
		return ErrInvalidKey
	}

	if msgType == MessageTypeFileWithFilename && (encConfig == nil || encConfig.OrigFilename == "") {
		return fmt.Errorf("Must specify original filename when encrypting file: %w",
			ErrInvalidEncryptConfig)
	}

	blake, err := blake2b.New512(nil)
	if err != nil {
		return err
	}

	//
	// Header: Generate it, encrypt it, hash it
	//

	header, err := NewHeader(msgType)
	if err != nil {
		return err
	}
	noncePlusEncryptedHeaderPlusHash, err := EncryptAndHashChunk(header, key, blake)
	if err != nil {
		return err
	}

	log.Debugf("EncryptReaderToWriter: header created, encrypted, and hashed successfully (though not yet written)")

	// Write this below, for efficiency's sake, and to not reveal much
	// about the structure of the files we're sending
	firstChunkEnc := noncePlusEncryptedHeaderPlusHash

	//
	// Encrypt filename if we are encrypting a file (and, thus, there is one)
	//

	if msgType == MessageTypeFileWithFilename {
		filenameChunk, err := NewFilenameChunk(encConfig.OrigFilename)
		if err != nil {
			return err
		}

		noncePlusFilename, err := EncryptAndHashChunk(filenameChunk, key, blake)
		if err != nil {
			return err
		}

		firstChunkEnc = append(firstChunkEnc, noncePlusFilename...)

		// FALL THROUGH
	}

	//
	// Encrypt and hash each chunk
	//

	isFirstChunkWritten := false
	var plainb [EncryptChunkLength]byte
	// staged chunk consisting of IsLastChunkByte + plain chunk
	var staged []byte

	// Closure helper ftw
	encryptAndWriteStaged := func() error {
		noncePlusEncryptedChunkPlusHash, err := EncryptAndHashChunk(staged, key, blake)
		if err != nil {
			return err
		}

		if !isFirstChunkWritten {
			// Write the header chunk + filename chunk (if exists) +
			// first data chunk all at once
			noncePlusEncryptedChunkPlusHash = append(firstChunkEnc,
				noncePlusEncryptedChunkPlusHash...)
		}

		log.Debugf("Writing chunk; first == %v, length == %v",
			!isFirstChunkWritten, len(noncePlusEncryptedChunkPlusHash))

		_, err = cipherFile.Write(noncePlusEncryptedChunkPlusHash)
		if err != nil {
			return err
		}
		staged = nil
		isFirstChunkWritten = true

		return nil
	}

	// Loop till 0 bytes read. Fuck EOF, which only complicates things
	for true {
		n, err := plainFile.Read(plainb[:])
		if err != nil && err != io.EOF {
			return err
		}

		if n > 0 {
			if len(staged) > 0 {
				// We have new data _and_ staged data, so set
				// `staged` as _not_ the last chunk, then encrypt
				// and write it.
				staged[0], err = IsLastChunkBoolToByte(false)
				if err != nil {
					return err
				}
				err = encryptAndWriteStaged()
				if err != nil {
					return err
				}
			}

			// We have new data and no staged data. This may be
			// the first iteration, and the current chunk may or
			// not be the last one. Let's prepend a dummy value,
			// then stage the chunk.
			staged = append([]byte{0}, plainb[:n]...)
			continue
		}

		if n == 0 && len(staged) > 0 {
			// We have no new data but we _do_ have staged
			// data. Therefore what is staged is the last
			// chunk. So let's mark it as such, then encrypt
			// and write it.
			staged[0], err = IsLastChunkBoolToByte(true)
			if err != nil {
				return err
			}
			err = encryptAndWriteStaged()
			if err != nil {
				return err
			}
			break
		}
	}

	return nil
}

func NewHeader(msgType uint16) ([]byte, error) {
	if msgType == MessageTypeInvalid || msgType > MaxMsgType {
		return nil, ErrInvalidMessageType
	}

	// Big endian
	header := []byte{
		// Message type
		byte(msgType >> 8),
		byte(msgType),
	}

	// assert len(header) == 2

	return header, nil
}

// NewFilenameChunk returns a []byte of length 256 with the following
// structure: `[ 1 byte: length of original filename || N bytes:
// original filename || 255 - N bytes: random data (padding) ]`
func NewFilenameChunk(origFilename string) ([]byte, error) {
	// Must convert to []byte first to correctly support UTF-8;
	// len(str) counts runes, not bytes
	lenOrigFilename := len([]byte(origFilename))

	if lenOrigFilename < MinFilenameLength || lenOrigFilename > MaxFilenameLength {
		return nil, fmt.Errorf("origFilename may not be %v: %w",
			lenOrigFilename, ErrInvalidFilenameLength)
	}

	// [  0 0 0 0 0 ... ]
	filenameChunk := make([]byte, EncryptFilenameChunkLength)

	// [ 14 0 0 0 0 ... ] where 14 == lenOrigFilename
	filenameChunk[0] = byte(lenOrigFilename)

	// [ 14 m y f i l e n a m e . t x t 0 0 0 0 0 ... ] where
	// origFilename == "myfilename.txt"
	n := copy(filenameChunk[1:], []byte(origFilename))
	if n != lenOrigFilename {
		return nil, fmt.Errorf("Only copied %v bytes of origFilename, not %v!", n, lenOrigFilename)
	}

	// [ 14 m y f i l e n a m e . t x t R A N D O M D A T A H E R E ... ]
	n, err := rand.Reader.Read(filenameChunk[1+lenOrigFilename:])
	if err != nil {
		return nil, err
	}
	nWanted := EncryptFilenameChunkLength - lenOrigFilename - 1
	if n != nWanted {
		return nil, fmt.Errorf("Only read %v random bytes, not %v!", n, nWanted)
	}

	return filenameChunk, nil
}

// EncryptAndHashChunk encrypts and hashes the given data. Unless you
// are encrypting a miniLeap header or filename, the first argument
// should consist of the data you want to encrypt prefixed by an
// "isLastChunk" byte.
func EncryptAndHashChunk(isLastChunkBytePlusPlain []byte, key *[ValidKeyLength]byte, blake hash.Hash) ([]byte, error) {
	isLastChunkBytePlusPlainLen := len(isLastChunkBytePlusPlain)
	if isLastChunkBytePlusPlainLen == 0 {
		return nil, fmt.Errorf("Cannot encrypt empty chunk")
	}
	if key == nil || *key == empty32ByteArray {
		return nil, ErrInvalidKey
	}

	nonce, err := RandomNonce()
	if err != nil {
		return nil, fmt.Errorf("Error generating nonce: %s", err)
	}
	nonceSlice := (*nonce)[:]

	cipherCapacity := isLastChunkBytePlusPlainLen + NonceCryptoBlakeOverhead

	// Start with length 0 and append from there so it's hard to
	// accidentally access the trailing zeroes belowsef, brosef
	cipher := make([]byte, 0, cipherCapacity)

	// Note: `blake.Write(...)` never returns error, as per `hash.Hash` spec
	blake.Write((*key)[:])

	cipher = append(cipher, nonceSlice...)
	cipher = secretbox.Seal(cipher, isLastChunkBytePlusPlain, nonce, key)
	blake.Write(cipher)

	blakeSum := blake.Sum(nil)
	cipher = append(cipher, blakeSum...)
	blake.Write(blakeSum) // It's almost like... a chain of blocks...

	if len(cipher) != cap(cipher) {
		return nil, fmt.Errorf("EncryptAndHashChunk: ciphertext is of length "+
			"%v but should be %v; something went wrong!", len(cipher), cap(cipher))
	}

	return cipher, nil
}

// IsLastChunkBoolToByte takes the given bool and turns it into a
// valid indicator that this is the last chunk if isLastChunk is true,
// or an indicator that this is not the last chunk if isLastChunk is
// false. (`isLastChunk == false` results in the returned byte being
// even, and `isLastChunk == true` results in the returned byte being
// odd.)
func IsLastChunkBoolToByte(isLastChunk bool) (byte, error) {
	randByte, err := RandByte()
	if err != nil {
		return 0, err
	}

	if isLastChunk {
		// Ensure odd
		return randByte | 1, nil
	}

	// Ensure even
	return randByte & 0xFE, nil
}

func RandByte() (byte, error) {
	b := make([]byte, 1)
	_, err := rand.Read(b)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

// From https://www.tutorialspoint.com/how-to-check-if-a-file-exists-in-golang
func FileExists(filename string) (bool, error) {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return !info.IsDir(), nil
}

func DirExists(dir string) (bool, error) {
	info, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return info.IsDir(), nil
}

func MustGetFromStdinSecure() string {
	input, err := ReadPassword()
	if err != nil {
		exit(err)
	}
	fmt.Fprintf(os.Stderr, "\n")

	return input
}

func exit(err error) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	os.Exit(1)
}

func ReadPassword() (string, error) {
	inputb, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	return string(inputb), err
}

func MustGetFromStdinStripped() string {
	reader := bufio.NewReader(os.Stdin)
	text, err := reader.ReadString('\n')
	if err != nil {
		exit(err)
	}
	return strings.TrimRight(text, "\r\n")
}

// RandomNonce generates and returns a new random nonce. RandomNonce
// guarantees that the returned nonce is not nil and is fully
// populated.
func RandomNonce() (*[NonceLength]byte, error) {
	var b [NonceLength]byte
	n, err := rand.Reader.Read(b[:])
	if err != nil {
		return nil, err
	}
	if n != NonceLength {
		return nil, fmt.Errorf("Only read %v random bytes, not %v!",
			n, NonceLength)
	}
	return &b, nil
}

func ConvertNonce(nonce []byte) (goodNonce *[NonceLength]byte, err error) {
	if len(nonce) != NonceLength {
		return nil, ErrInvalidNonce
	}
	var b [NonceLength]byte
	n := copy(b[:], nonce[:])
	if n != NonceLength {
		return nil, fmt.Errorf("Error converting nonce; got %v bytes, wanted %v",
			n, NonceLength)
	}
	return &b, nil
}

func ConvertKey(key []byte) (goodKey *[ValidKeyLength]byte, err error) {
	if len(key) != ValidKeyLength {
		return nil, fmt.Errorf("Invalid key; must be of length %d, has length %d",
			ValidKeyLength, len(key))
	}

	// []byte -> *[ValidKeyLength]byte
	var good [ValidKeyLength]byte

	n := copy(good[:], key)
	if n != ValidKeyLength {
		return nil, ErrInvalidKeyLength
	}

	return &good, nil
}

func Base58DecodeAccountID(accountID string) ([]byte, error) {
	signPubKey, err := base58.StdEncoding.Decode([]byte(accountID))
	if err != nil {
		return nil, err
	}
	if len(signPubKey) != 32 {
		return nil, fmt.Errorf("Decoded account ID's length is %v, should be 32",
			len(signPubKey))
	}
	return signPubKey, nil
}

func AccountIDToCurve25519(accountID string) ([]byte, error) {
	signPubKey, err := Base58DecodeAccountID(accountID)
	if err != nil {
		return nil, err
	}

	curvePub, err := PublicEd25519ToCurve25519(signPubKey)
	if err != nil {
		return nil, err
	}

	return curvePub, nil
}

func MustWipeKeys(keyPair *taber.Keys, keyPairPrivate32 *[32]byte) {
	err := keyPair.Wipe()
	err2 := taber.WipeKeyArray(keyPairPrivate32)

	if err != nil {
		log.Fatalf("Error wiping keyPair: %v\n", err)
	}
	if err2 != nil {
		log.Fatalf("Error wiping keyPairPrivate32: %v\n", err2)
	}
}
