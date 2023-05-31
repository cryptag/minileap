package minileap

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"strings"

	"github.com/cryptag/go-minilock/taber"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	NonceLength        = 24
	EncryptChunkLength = 1_000_000
	Blake2bHashLength  = blake2b.Size

	// 104 == 24 + 16 + 64. Does not include IsLastChunkIndicatorLength
	NonceCryptoBlakeOverhead = NonceLength + secretbox.Overhead + Blake2bHashLength

	// 3-byte chunk size (big endian) || 2-byte message type (big endian)
	EncryptHeaderLength = 5

	DecryptHeaderLength = EncryptHeaderLength + NonceCryptoBlakeOverhead

	// EncryptChunkLength tells us how big a chunk should be encrypted
	// at once. Default: 1 million bytes. TODO: Make configurable.
	IsLastChunkIndicatorLength = 1

	// Use DecryptChunkLength when decrypting
	DecryptChunkOverhead = IsLastChunkIndicatorLength + NonceCryptoBlakeOverhead

	ValidKeyLength = 32

	MiniLeapFileExtension             = "minileap"
	MiniLeapFileExtensionIncludingDot = "." + MiniLeapFileExtension
)

const (
	MinChunkLength = int(1 << 10)      //      1,024
	MaxChunkLength = int(1<<24 - 1)    // 16,777,215
	MaxMsgType     = uint16(1<<16 - 1) //     65,535

	//
	// Message types
	//
	MessageTypeInvalid                 = uint16(0)
	MessageTypeChatMessage             = uint16(1)
	MessageTypeURL                     = uint16(2)
	MessageTypeCommand                 = uint16(3)
	MessageTypePassphrase              = uint16(4)
	MessageTypeFileWithFilename        = uint16(5)
	MessageTypeFileWithFilenameAndPath = uint16(6)
)

var (
	ErrInvalidNonce          = fmt.Errorf("Invalid nonce")
	ErrInvalidKey            = fmt.Errorf("Invalid key")
	ErrInvalidKeyLength      = fmt.Errorf("Invalid key length")
	ErrInvalidChunkLength    = fmt.Errorf("Header: invalid chunk length")
	ErrInvalidMessageType    = fmt.Errorf("Header: invalid message type")
	ErrChunkDecryptionFailed = fmt.Errorf("Chunk decryption failed")
	ErrInvalidChunkHash      = fmt.Errorf("Invalid chunk hash")
	ErrInvalidFinalHash      = fmt.Errorf("Invalid final hash")

	TestKey = &[ValidKeyLength]byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1,
	}
)

func EncryptFile(filename string, key *[32]byte, dest string, forceOverwrite bool) (cipherFilename string, err error) {
	if key == nil || *key == [32]byte{} {
		return "", ErrInvalidKey
	}

	// TODO: Make the name and location of resulting encrypted
	// file configurable with `-o <outfile>` option or similar

	cipherFilename = dest
	if dest == "" {
		// Save encrypted file with ".minileap" extension appended
		cipherFilename = filename + MiniLeapFileExtensionIncludingDot
	}

	if FileExists(cipherFilename) && !forceOverwrite {
		return cipherFilename, fmt.Errorf("Encrypted file `%s` already exists and you've chosen not to overwrite existing files!", cipherFilename)
	}

	plainFile, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer plainFile.Close()

	cipherFile, err := os.Create(cipherFilename)
	if err != nil {
		return cipherFilename, err
	}
	defer cipherFile.Close()

	// TODO: Add the filename in the first non-header chunk,
	// padded to 255 bytes.  Make the first byte specify the
	// length of the filename if needed, thus resulting in the
	// first non-header chunk size being 256 bytes.

	blake, err := blake2b.New512((*key)[:])
	if err != nil {
		return cipherFilename, err
	}

	//
	// Header: Generate it, encrypt it, hash it
	//

	header, err := NewHeader(EncryptChunkLength, MessageTypeFileWithFilename)
	if err != nil {
		return cipherFilename, err
	}
	noncePlusEncryptedHeaderPlusHash, err := EncryptAndHashChunk(header, key, blake)
	if err != nil {
		return cipherFilename, err
	}
	_, err = cipherFile.Write(noncePlusEncryptedHeaderPlusHash)
	if err != nil {
		return cipherFilename, err
	}

	//
	// Encrypt and hash each chunk
	//

	var plainb [EncryptChunkLength]byte
	// staged chunk consisting of IsLastChunkByte + plain chunk
	var staged []byte

	// Closure helper ftw
	encryptAndWriteStaged := func() error {
		noncePlusEncryptedChunkPlusHash, err := EncryptAndHashChunk(staged, key, blake)
		if err != nil {
			return err
		}
		_, err = cipherFile.Write(noncePlusEncryptedChunkPlusHash)
		if err != nil {
			return err
		}
		staged = nil

		return nil
	}

	// Loop till 0 bytes read. Fuck EOF, which only complicates things
	for true {
		n, err := plainFile.Read(plainb[:])
		if err != nil && err != io.EOF {
			return cipherFilename, err
		}

		if n > 0 {
			if len(staged) > 0 {
				// We have new data _and_ staged data, so set
				// `staged` as _not_ the last chunk, then encrypt
				// and write it.
				staged[0] = IsLastChunkBoolToByte(false)
				err = encryptAndWriteStaged()
				if err != nil {
					return cipherFilename, err
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
			staged[0] = IsLastChunkBoolToByte(true)
			err = encryptAndWriteStaged()
			if err != nil {
				return cipherFilename, err
			}
			break
		}
	}

	return cipherFilename, nil
}

func NewHeader(chunkLength int, msgType uint16) ([]byte, error) {
	if chunkLength < MinChunkLength || chunkLength > MaxChunkLength {
		return nil, ErrInvalidChunkLength
	}

	if msgType == MessageTypeInvalid || msgType > MaxMsgType {
		return nil, ErrInvalidMessageType
	}

	// Both are in big endian
	header := []byte{
		// Only working with chunkLength's lowest 3 bytes since it's a
		// uint24

		// Chunk size, aka chunk length
		byte(chunkLength >> 16),
		byte(chunkLength >> 8),
		byte(chunkLength),

		// Message type
		byte(msgType >> 8),
		byte(msgType),
	}

	// assert len(header) == 5

	return header, nil
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

	cipher = append(cipher, nonceSlice...)
	cipher = secretbox.Seal(cipher, isLastChunkBytePlusPlain, nonce, key)
	blake.Write(cipher)

	blakeSum := blake.Sum(nil)
	cipher = append(cipher, blakeSum...)
	blake.Write(blakeSum) // Roll baby roll

	if len(cipher) != cap(cipher) {
		return nil, fmt.Errorf("EncryptAndHashChunk: ciphertext is of length "+
			"%v but should be %v; something went wrong!", len(cipher), cap(cipher))
	}

	return cipher, nil
}

func IsLastChunkBoolToByte(isLastChunk bool) byte {
	// TODO: Make more dynamic and harder to guess
	if isLastChunk {
		return 1
	}
	return 0
}

// From https://www.tutorialspoint.com/how-to-check-if-a-file-exists-in-golang
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func MustGetFromStdinSecure() string {
	input, err := ReadPassword()
	if err != nil {
		exit(err)
	}
	fmt.Println("")

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
