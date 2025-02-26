package minileap

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	slash = string(filepath.Separator)
)

var (
	ErrNotLastChunk = errors.New("The file just decrypted may have been truncated! Or it could be a bug in the code that did the encryption, or, most likely, we've just decrypted the beginning of a miniLeap file, but not the whole thing; that's all we know.")
)

// DecrytFile decrypts the file located at cipherFilename to the
// destination directory dest. If dest == "-", the decrypted miniLeap
// message will be written to stdout, discarding the filename if the
// underlying message type is MessageTypeFileWithFilename.
func DecryptFile(cipherFilename string, key *[32]byte, dest string, forceOverwrite bool) (*EncryptionConfig, error) {
	if key == nil || *key == empty32ByteArray {
		return nil, ErrInvalidKey
	}

	config := &EncryptionConfig{}
	plainFile := os.Stdout
	var plainFilename string

	if dest != "-" {
		if strings.HasSuffix(cipherFilename, MiniLeapFileExtensionIncludingDot) {
			// Save decrypted file with `.minileap` extension removed
			plainFilename = cipherFilename[:len(cipherFilename)-len(MiniLeapFileExtensionIncludingDot)]
		} else {
			plainFilename = cipherFilename + ".dec"
		}

		// Prepend destination dir to `plainFilename`
		plainFilename = filepath.Clean(dest) + slash + filepath.Base(plainFilename)
		exists, err := FileExists(plainFilename)
		if err != nil {
			return nil, err
		}

		if exists && !forceOverwrite {
			return nil, fmt.Errorf("Intermediate destination file `%s` already"+
				" exists and you've chosen not to overwrite existing files!",
				plainFilename)
		}

		//
		// Set 2 global-ish vars
		//

		config.OrigFilename = plainFilename

		plainFile, err = os.Create(plainFilename)
		if err != nil {
			return config, err
		}
		defer plainFile.Close()

		// FALL THROUGH
	}

	// TODO: Run `os.Remove(plainFilename)` on error

	cipherFile, err := os.Open(cipherFilename)
	if err != nil {
		return config, err
	}
	defer cipherFile.Close()

	// TODO: Consider changing this very function's signature to
	// return `config` instead of `plainFilename`

	// Set global-ish var `config`
	config, err = DecryptReaderToWriter(cipherFile, key, &EncryptionConfig{PlainFile: plainFile})
	if err != nil {
		return config, err
	}

	// We have now decrypted cipherFilename and saved it to
	// plainFilename, but if config.OrigFilename is populated then we
	// should really save it there instead so as to preserve the
	// original filename.

	// Try renaming to the correct (original) filename
	if dest != "-" && config.OrigFilename != filepath.Base(plainFilename) {
		origFilename := filepath.Clean(dest) + slash + filepath.Base(config.OrigFilename)
		exists, err := FileExists(origFilename)
		if err != nil {
			return config, err
		}

		if exists && !forceOverwrite {
			// TODO: Decide whether to return error here
			fmt.Fprintf(os.Stderr, "File successfully decrypted to `%s`."+
				" Unencrypted file `%s` already exists and you've chosen not"+
				" to overwrite existing files! NOT renaming decrypted file"+
				" `%[1]s` to `%[2]s` as you requested, sorry!\n",
				plainFilename, origFilename)

			config.SavedLocation = filepath.Clean(dest) + slash + filepath.Base(plainFilename)

			return config, nil
		}

		err = os.Rename(plainFilename, origFilename)
		if err != nil {
			return config, nil
		}

		config.OrigFilename = origFilename

		// FALL THROUGH
	}

	return config, nil
}

// DecryptReaderToWriter performs streaming decryption on `cipherFile`
// using `key` and writes the decrypted result to `config.PlainFile`.
// `config.OrigFilename` will be non-empty if cipherFile is of type
// `MessageTypeFileWithFilename`. `config` may be non-nil even in the
// case of an error in order to relay potentially-relevant information
// to the caller (particularly when `err == ErrNotLastChunk`). If
// `blake == nil` this means we are decrypting the first chunk in a
// miniLeap file, and a new Blake2b hasher will be created and
// used. Callers who receive `err == ErrNotLastChunk` should use
// `config.Blake` to call this function again to decrypt subsequent
// chunks until `err == nil` is returned.
//
// If `encConfig.PlainFile == nil` and we are decrypting a miniLeap
// message of type `MessageTypeFileWithFilename`, the resulting
// `*os.File` will be stored in `config.PlainFile` and have the
// decrypted file contents written to it.
//
// If `encConfig.PlainFile == nil` and it turns out we are not
// decrypting a file, this function will set `config.PlainFile` equal
// to a new `*bytes.Buffer` and write decrypted contents to it (e.g.,
// a chat message).
func DecryptReaderToWriter(cipherFile io.Reader, key *[32]byte, encConfig *EncryptionConfig) (config *EncryptionConfig, err error) {
	if key == nil || *key == empty32ByteArray {
		return nil, ErrInvalidKey
	}

	if encConfig == nil {
		encConfig = &EncryptionConfig{}
	}
	blake := encConfig.Blake

	// Assume for now that we are not decrypting the first chunk, so
	// copy these fields, which may or may not be empty:
	config = &EncryptionConfig{
		// BlobID:       encConfig.BlobID,
		MsgType:      encConfig.MsgType,
		OrigFilename: encConfig.OrigFilename,
		PlainFile:    encConfig.PlainFile,
	}

	// ...but if we _are_ currently decrypting the first chunk:
	if blake == nil {
		// Will be overridden below if it should be
		config.PlainFile = &bytes.Buffer{}

		var err error

		// Set global-ish var
		blake, err = blake2b.New512(nil)
		if err != nil {
			return nil, err
		}

		//
		// Header: Decrypt it, verify its hash, set `config.MsgType`
		// and, if we're decrypting a MessageTypeFileWithFilename,
		// also set `config.OrigFilename`
		//

		noncePlusEncryptedHeaderPlusHash := make([]byte, DecryptHeaderLength)
		n, err := cipherFile.Read(noncePlusEncryptedHeaderPlusHash)
		if err != nil {
			return nil, err
		}

		if n != DecryptHeaderLength {
			return nil, fmt.Errorf("Decrypting header: Wanted %v bytes, got %v",
				DecryptHeaderLength, n)
		}

		log.Debugf("Decrypting and verifying header chunk...")

		header, err := DecryptAndVerifyChunk(noncePlusEncryptedHeaderPlusHash, key, blake)
		if err != nil {
			return nil, err
		}

		msgType, err := ParseDecryptedHeaderIntoValidFields(header)
		if err != nil {
			return nil, err
		}

		// Set global-ish var
		config.MsgType = msgType

		log.Debugf("Parsed header; msgType: `%s`", MessageTypeName(msgType))

		//
		// Decrypt filename chunk if we are decrypting a file (and, thus, there is one)
		//

		if msgType == MessageTypeFileWithFilename {
			noncePlusEncryptedChunkPlusHash := make([]byte, EncryptFilenameChunkLength+NonceCryptoBlakeOverhead)
			n, err := cipherFile.Read(noncePlusEncryptedChunkPlusHash)
			if err != nil && err != io.EOF {
				return nil, err
			}

			if n != cap(noncePlusEncryptedChunkPlusHash) {
				return nil, fmt.Errorf("Error decrypting filename: Wanted to read"+
					" %v bytes, read %v bytes instead!",
					cap(noncePlusEncryptedChunkPlusHash), n)
			}

			log.Debugf("Decrypting and verifying filename chunk...")

			decryptedFilenameBytes, err := DecryptAndVerifyChunk(noncePlusEncryptedChunkPlusHash, key, blake)
			if err != nil {
				return nil, err
			}

			// Filename length stored in first byte
			realLength := int(decryptedFilenameBytes[0])

			// Grab everything after the first byte and before the
			// trailing random padding
			decryptedFilename := string(decryptedFilenameBytes[1 : 1+realLength])

			for _, char := range InvalidFilenameChars {
				if strings.Contains(decryptedFilename, char) {
					return nil, fmt.Errorf("Decrypted filename `%s` contains"+
						" invalid character `%s`!", decryptedFilename, char)
				}
			}

			// Set global-ish var
			config.OrigFilename = decryptedFilename

			// Overwrite `config.PlainFile`

			// Goal: if `./${decryptedFilename}` does not exists,
			// create config.PlainFile there, otherwise do kind of like
			// what Windows does and add `-1` right before the
			// file extension, or `-2`, etc.

			exists, _ := FileExists(decryptedFilename)
			if !exists {
				// Happy case: we don't have to fuck around with
				// adding a numerical suffix to
				// `decryptedFilename`; just use it directly to
				// create `config.PlainFile` at that location

				// Set global-ish var
				config.PlainFile, err = os.Create(decryptedFilename)
				if err != nil {
					return nil, fmt.Errorf("Error creating `%s` -- %w",
						decryptedFilename, err)
				}
				// `config.PlainFile.Close()` is called below

			} else {
				// assert exists == true
				plainFilenamePrefix := decryptedFilename
				ndx := strings.LastIndex(plainFilenamePrefix, ".")
				origNdx := ndx
				if ndx == -1 {
					// Removed below
					plainFilenamePrefix = decryptedFilename + "."
					ndx = strings.LastIndex(plainFilenamePrefix, ".")
				}

				suffixNum := 0
				var plainFilename string
				for exists {
					suffixNum++
					plainFilename = fmt.Sprintf("%v-%d.%v",
						plainFilenamePrefix[:ndx],
						suffixNum,
						plainFilenamePrefix[ndx+1:],
					)

					// Trim off trailing "." if there is one
					if origNdx == -1 && strings.HasSuffix(plainFilename, ".") {
						plainFilename = plainFilename[:len(plainFilename)-1]
					}

					exists, _ = FileExists(plainFilename)
				}

				// Finally got a non-existent file with a suitable name!

				// TODO: Make destination dir configurable;
				// implicitly defaults to ".", sitting right next
				// to the `relay` binary.

				// Set global-ish var
				config.PlainFile, err = os.Create(plainFilename)
				if err != nil {
					return nil, fmt.Errorf("Error creating `%s` -- %w",
						plainFilename, err)
				}
				// `config.PlainFile.Close()` is called below

				config.OrigFilename = plainFilename

				// FALL THROUGH
			}
		}

		// Header fully verified :ok_hand:
		log.Debugf("Header chunk: Successfully decrypted, verified, and parsed %s",
			MessageTypeName(msgType))
	}

	log.Debugf("Writing to config.PlainFile of type %T", config.PlainFile)

	// assert config.MsgType != 0

	// if config.MsgType == MessageTypeFileWithFilename {
	//     assert config.OrigFilename != ""
	// }

	//
	// Decrypt and verify data chunks
	//

	var n int
	isLastChunk := false
	noncePlusEncryptedChunkPlusHash := make([]byte, EncryptChunkLength+DecryptChunkOverhead)
	for {
		n, err = cipherFile.Read(noncePlusEncryptedChunkPlusHash)
		if err != nil && err != io.EOF {
			return config, err
		}

		log.Debugf("Read %v bytes from cipherFile", n)

		if n == 0 {
			break
		}

		isLastPlusDecryptedChunk, err := DecryptAndVerifyChunk(noncePlusEncryptedChunkPlusHash[:n], key, blake)
		if err != nil {
			// TODO: Set `config.Leftovers = noncePlusEncryptedChunkPlusHash[:n]`
			// and `config.Blake = blake` as long as `err != ErrInvalidChunkHash`?
			// And return special error indicating a partial chunk decryption
			// failure?
			return config, err
		}

		isLastChunk = IsLastChunkByte(isLastPlusDecryptedChunk[0])

		_, err = config.PlainFile.Write(isLastPlusDecryptedChunk[1:])
		if err != nil {
			return config, err
		}

		if isLastChunk {
			break
		}
	}

	if !isLastChunk {
		log.Debugf("DecryptReaderToWriter: Returning without getting a last chunk; successfully decrypted everything else, though")

		config.Blake = blake

		return config, ErrNotLastChunk
	}

	// assert isLastChunk

	// Close file opened to store decrypted contents
	if plainFile, ok := config.PlainFile.(*os.File); ok && plainFile != os.Stdout {
		// TODO: Handle error(?)
		_ = plainFile.Close()
	}

	log.Debugf("DecryptReaderToWriter: Successfully decrypted and wrote last chunk; total success")

	return config, nil
}

func DecryptAndVerifyChunk(noncePlusEncryptedChunkPlusHash []byte, key *[ValidKeyLength]byte, blake hash.Hash) ([]byte, error) {
	if len(noncePlusEncryptedChunkPlusHash) <= NonceCryptoBlakeOverhead {
		return nil, ErrInvalidChunkLength
	}
	if key == nil || *key == empty32ByteArray {
		return nil, ErrInvalidKey
	}

	log.Debugf("Decrypting and verifying %v-byte nonce + ciphertext + hash",
		len(noncePlusEncryptedChunkPlusHash))

	// Layout: `[ 24 bytes: nonce || 1 + N + 16 bytes: 1 isLastChunk byte, N encrypted bytes, 16 overhead bytes || 64 bytes: Blake2b hash ]`

	nonce, err := ConvertNonce(noncePlusEncryptedChunkPlusHash[:NonceLength])
	if err != nil {
		return nil, err
	}
	cipher := noncePlusEncryptedChunkPlusHash[NonceLength : len(noncePlusEncryptedChunkPlusHash)-Blake2bHashLength]

	log.Debugf("DecryptAndVerifyChunk: Decrypting %v bytes from %v-byte chunk...",
		len(cipher), len(noncePlusEncryptedChunkPlusHash))

	// Decrypt
	plain, ok := secretbox.Open(nil, cipher, nonce, key)
	if !ok {
		return nil, fmt.Errorf("DecryptAndVerifyChunk: Error decrypting %v-byte secretbox message: %w",
			len(cipher), ErrChunkDecryptionFailed)
	}

	// Note: `blake.Write(...)` never returns error, as per `hash.Hash` spec
	blake.Write((*key)[:])
	blake.Write(noncePlusEncryptedChunkPlusHash[:NonceLength])
	blake.Write(cipher)

	blakeSum := blake.Sum(nil)

	gotBlakeHash := noncePlusEncryptedChunkPlusHash[len(noncePlusEncryptedChunkPlusHash)-Blake2bHashLength:]
	if subtle.ConstantTimeCompare(gotBlakeHash, blakeSum) == 0 {
		return nil, ErrInvalidChunkHash
	}

	blake.Write(blakeSum)

	return plain, nil
}

func ParseDecryptedHeaderIntoValidFields(headerb []byte) (msgType uint16, err error) {
	if len(headerb) != EncryptHeaderLength {
		err = fmt.Errorf("Decrypted header is %v bytes, expected %v\n", len(headerb), EncryptHeaderLength)
		return
	}

	msgType = uint16(headerb[0])<<8 | uint16(headerb[1])

	if msgType == MessageTypeInvalid {
		err = ErrInvalidMessageType
		return
	}

	return
}

// IsLastChunkByte checks whether the given byte indicates that the
// chunk it represents is the last chunk in a miniLeap message. (An
// even byte means this is not a last chunk byte, an odd one means it
// is.)
func IsLastChunkByte(isLastChunk byte) bool {
	return isLastChunk&1 == 1
}

func MustDeriveIdentityFromUserInput(requirePassphrase bool, email string) *Identity {
	if requirePassphrase {
		fmt.Fprintf(os.Stderr, "Passphrase: ")
	} else {
		fmt.Fprintf(os.Stderr, "Passphrase (leave blank to generate new, random passphrase): ")
	}
	passphrase := MustGetFromStdinSecure()

	if len(passphrase) == 0 {
		if requirePassphrase {
			exit(fmt.Errorf("Passphrase required but not provided"))
		}

		var err error
		passphrase, err = RandomPassphrase(25)
		if err != nil {
			exit(err)
		}

		fmt.Fprintf(os.Stderr, "Passphrase: %s\n", passphrase)
	}

	if len(email) == 0 {
		email = EmailFromPassphrase(passphrase)
	}

	ident, err := NewIdentity(email, passphrase)
	if err != nil {
		exit(err)
	}

	return ident
}
