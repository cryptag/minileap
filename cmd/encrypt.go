package cmd

import (
	"bufio"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"strings"

	"github.com/cryptag/go-minilock/taber"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/ssh/terminal"
)

func init() {
	rootCmd.AddCommand(encryptCmd)
}

const (
	// EncryptChunkLength tells us how big a chunk should be encrypted
	// at once. Default: 1 million bytes. TODO: Make configurable.
	EncryptChunkLength = 1_000_000
	NonceLength        = 24
	Blake2bHashLength  = blake2b.Size
	Sha512HashLength   = 64

	// 104 == 24 + 16 + 64
	TotalChunkOverhead = NonceLength + secretbox.Overhead + Blake2bHashLength

	// Use DecryptChunkLength when decrypting. Default length: 1
	// million 104 bytes; 1 million bytes of decrypted content +
	// 24-byte nonce + 16 bytes of encryption overhead + 64 bytes of
	// Blake2b hash.
	DecryptChunkLength = EncryptChunkLength + TotalChunkOverhead

	// 4-byte chunk size (big endian) || 2-byte message type (big endian)
	EncryptHeaderLength = 6

	DecryptHeaderLength = EncryptHeaderLength + TotalChunkOverhead

	ValidKeyLength = 32
)

const (
	MinChunkLength = int32(1 << 10)   //         1,024
	MaxChunkLength = int32(1<<31 - 1) // 2,147,483,647
	MaxMsgType     = int16(1<<15 - 1) //        32,767

	//
	// Message types
	//
	MessageTypeZero                    = int16(0) // Invalid
	MessageTypeChatMessage             = int16(1)
	MessageTypeURL                     = int16(2)
	MessageTypeCommand                 = int16(3)
	MessageTypePassphrase              = int16(4)
	MessageTypeFileWithFilename        = int16(5)
	MessageTypeFileWithFilenameAndPath = int16(6)
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

	KeyPair          *taber.Keys
	KeyPairPrivate32 *[ValidKeyLength]byte

	TestKey = &[ValidKeyLength]byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		0, 1,
	}
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt-file",
	Short: "Encrypt the given file with the given email/passphrase combination",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			exit(fmt.Errorf("Usage: minileap encrypt-file <filename> [ <filename2> ... ]"))
		}

		// assert len(args) >= 1

		// TODO: Loop over all files listed
		filename := args[0]

		// Derive keypair from user-specified email and password

		KeyPair = MustDeriveKeypairFromUserInput()
		defer wipeAll()

		var err error
		KeyPairPrivate32, err = ConvertKey(KeyPair.Private)
		if err != nil {
			exit(err)
		}

		mID, err := KeyPair.EncodeID()
		if err != nil {
			exit(err)
		}

		//
		// Use not-so-fancy crypto to encrypt with user keypair
		//

		fmt.Printf("Using miniLock ID %s to derive symmetric key to encrypt file %s ...\n", mID, filename)

		plainFile, err := os.Open(filename)
		if err != nil {
			exit(err)
		}
		defer plainFile.Close()

		// plainFileInfo, err := plainFile.Stat()
		// if err != nil {
		// 	exit(err)
		// }
		// plainFileLength := plainFileInfo.Size()

		// TODO: Make the name and location of resulting encrypted
		// file configurable with `-o <outfile>` option or similar

		// Save encrypted file with ".enc" extension appended
		cipherFilename := filename + ".enc"

		if fileExists(cipherFilename) {
			exit(fmt.Errorf("Cannot save new file `%s`; file already exists at that location", cipherFilename))
		}

		cipherFile, err := os.Create(cipherFilename)
		if err != nil {
			exit(err)
		}
		defer cipherFile.Close()

		// TODO: Add the filename in the first non-header chunk,
		// padded to 255 bytes.  Make the first byte specify the
		// length of the filename if needed, thus resulting in the
		// first non-header chunk size being 256 bytes.

		// Hashers ftw
		blake, err := blake2b.New512(KeyPair.Private)
		if err != nil {
			exit(err)
		}
		sha512Append := sha512.New()
		sha512Append.Write(KeyPair.Private)

		//
		// Header: Generate it, encrypt it, hash it
		//

		// TODO: Check for `int32(EncryptChunkLength)` overflow

		header, err := NewHeader(int32(EncryptChunkLength), MessageTypeFileWithFilename)
		if err != nil {
			exit(err)
		}
		noncePlusEncryptedHeaderPlusHash, err := EncryptAndHashChunk(header, KeyPairPrivate32, blake)
		if err != nil {
			exit(err)
		}
		_, err = cipherFile.Write(noncePlusEncryptedHeaderPlusHash)
		if err != nil {
			exit(err)
		}
		// Never returns error, as per `hash.Hash` spec
		sha512Append.Write(noncePlusEncryptedHeaderPlusHash)

		//
		// Encrypt and hash each chunk
		//

		var plainb [EncryptChunkLength]byte
		var n int
		for true { // Loop till EOF
			n, err = plainFile.Read(plainb[:])
			if err != nil && err != io.EOF {
				exit(err)
			}

			if n == 0 {
				break
			}

			endOfFile := (err == io.EOF)

			noncePlusEncryptedChunkPlusHash, err := EncryptAndHashChunk(plainb[:n], KeyPairPrivate32, blake)
			if err != nil {
				exit(err)
			}

			_, err = cipherFile.Write(noncePlusEncryptedChunkPlusHash)
			if err != nil {
				exit(err)
			}

			sha512Append.Write(noncePlusEncryptedChunkPlusHash)

			if endOfFile {
				break
			}
		}

		// Append final sha512 hash
		_, err = cipherFile.Write(sha512Append.Sum(nil))
		if err != nil {
			exit(err)
		}

		fmt.Printf("File successfully encrypted and saved to %s\n", cipherFilename)
	},
}

func wipeAll() {
	err := KeyPair.Wipe()
	err2 := taber.WipeKeyArray(KeyPairPrivate32)

	if err != nil {
		log.Fatalf("Error wiping KeyPair: %v\n", err)
	}
	if err2 != nil {
		log.Fatalf("Error wiping KeyPairPrivate32: %v\n", err2)
	}
}

func NewHeader(chunkLength int32, msgType int16) ([]byte, error) {
	if chunkLength < MinChunkLength || chunkLength > MaxChunkLength {
		return nil, ErrInvalidChunkLength
	}

	if msgType == MessageTypeZero || msgType > MaxMsgType {
		return nil, ErrInvalidMessageType
	}

	// Both are in big endian
	header := []byte{
		// Chunk size, aka chunk length
		byte(chunkLength >> 24),
		byte(chunkLength >> 16),
		byte(chunkLength >> 8),
		byte(chunkLength),

		// Message type
		byte(msgType >> 8),
		byte(msgType),
	}

	// assert len(header) == 6

	return header, nil
}

func EncryptAndHashChunk(plain []byte, key *[ValidKeyLength]byte, blake hash.Hash) ([]byte, error) {
	plainLen := len(plain)
	if plainLen == 0 {
		return nil, fmt.Errorf("Cannot encrypt empty chunk")
	}

	// if plainLen > EncryptChunkLength {
	// 	return nil, fmt.Errorf("Chunk too big (%v, must be %v max); use EncryptFile() instead", plainLen, EncryptChunkLength)
	// }

	// `plainLen < EncryptChunkLength` is OK (for last chunk)

	nonce, err := RandomNonce()
	if err != nil {
		return nil, fmt.Errorf("Error generating nonce: %s", err)
	}
	nonceSlice := (*nonce)[:]

	// aka plainLen + TotalChunkOverhead
	cipherCapacity := NonceLength + plainLen + secretbox.Overhead + Blake2bHashLength

	// Start with length 0 and append from there so it's hard to
	// accidentally access the trailing zeroes belowsef, brosef
	cipher := make([]byte, 0, cipherCapacity)

	// Note: `blake.Write(...)` never returns error, as per `hash.Hash` spec

	cipher = append(cipher, nonceSlice...)
	fmt.Printf("cipher before: len = %v, cap = %v\n", len(cipher), cap(cipher))
	cipher = secretbox.Seal(cipher, plain, nonce, key)
	fmt.Printf("cipher after:  len = %v, cap = %v\n", len(cipher), cap(cipher))
	blake.Write(cipher)

	blakeSum := blake.Sum(nil)
	cipher = append(cipher, blakeSum...)
	blake.Write(blakeSum) // Roll baby roll

	if len(cipher) != cap(cipher) {
		return nil, fmt.Errorf("EncryptAndHashChunk: ciphertext is of length "+
			"%v but should be %v; something went wrong!", len(cipher), cap(cipher))
	}

	// TODO: Consider doing this instead, since it's more
	// efficient... as long as it's correct (I need `blakeSum`, don't
	// I...)
	//
	// blake.Write(cipher)

	fmt.Printf("EncryptAndHashChunk: just wrote %v bytes:\n    %v\n\n", len(cipher), cipher)

	return cipher, nil
}

// From https://www.tutorialspoint.com/how-to-check-if-a-file-exists-in-golang
func fileExists(filename string) bool {
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
