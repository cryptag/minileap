package minileap

import (
	"crypto/subtle"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cryptag/go-minilock/taber"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/nacl/secretbox"
)

func DecryptFile(cipherFilename string, key *[32]byte, dest string, forceOverwrite bool) (plainFilename string, err error) {
	if key == nil || *key == [32]byte{} {
		return "", ErrInvalidKey
	}

	if strings.HasSuffix(cipherFilename, MiniLeapFileExtensionIncludingDot) {
		// Save decrypted file with `.minileap` extension removed
		plainFilename = cipherFilename[:len(cipherFilename)-len(MiniLeapFileExtensionIncludingDot)]
	}

	if plainFilename == "" {
		plainFilename = cipherFilename + ".dec"
	}

	// Prepend destination dir to `plainFilename`
	slash := string(filepath.Separator)
	plainFilename = filepath.Clean(dest) + slash + filepath.Base(plainFilename)

	exists, err := FileExists(plainFilename)
	if err != nil {
		return plainFilename, err
	}

	if exists && !forceOverwrite {
		return plainFilename, fmt.Errorf("Unencrypted file `%s` already exists and you've chosen not to overwrite existing files!", plainFilename)
	}

	cipherFile, err := os.Open(cipherFilename)
	if err != nil {
		return "", err
	}
	defer cipherFile.Close()

	plainFile, err := os.Create(plainFilename)
	if err != nil {
		return plainFilename, err
	}
	defer plainFile.Close()

	// TODO: Consider changing this function signature to return
	// `config` instead of `plainFilename`

	config, err := DecryptReaderToWriter(cipherFile, key, plainFile)
	if err != nil {
		return plainFilename, err
	}

	// Try renaming to the correct (original) filename
	if config.OrigFilename != filepath.Base(plainFilename) {
		origFilename := filepath.Clean(dest) + slash + filepath.Base(config.OrigFilename)
		exists, err := FileExists(origFilename)
		if err != nil {
			return plainFilename, err
		}

		if exists && !forceOverwrite {
			// TODO: Decide whether to return error here
			fmt.Fprintf(os.Stderr, "Unencrypted file `%s` already exists and"+
				" you've chosen not to overwrite existing files! NOT renaming"+
				" decrypted file `%s` to `%s` like you requested.\n",
				origFilename, plainFilename, origFilename)

			return plainFilename, nil
		}

		err = os.Rename(plainFilename, origFilename)
		if err != nil {
			return plainFilename, nil
		}

		// Return location of where file ended up (after renaming)
		return origFilename, nil
	}

	return plainFilename, nil
}

// DecryptReaderToWriter performs streaming decryption on cipherFile
// using key and writes the decrypted result to plainFile.
// config.OrigFilename will be non-empty if cipherFile is of type
// MessageTypeFileWithFilename. config may be non-nil even in the case
// of an error in order to relay potentially-relevant information to
// the caller.
func DecryptReaderToWriter(cipherFile io.Reader, key *[32]byte, plainFile io.Writer) (config *EncryptionConfig, err error) {
	// TODO: Run `os.Remove(plainFilename)` on error

	if key == nil || *key == [32]byte{} {
		return nil, ErrInvalidKey
	}

	// Hashers ftw
	blake, err := blake2b.New512((*key)[:])
	if err != nil {
		return nil, err
	}

	//
	// Header: Decrypt it, verify its hash
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

	header, err := DecryptAndVerifyChunk(noncePlusEncryptedHeaderPlusHash, key, blake)
	if err != nil {
		return nil, err
	}

	msgType, err := ParseDecryptedHeaderIntoValidFields(header)
	if err != nil {
		return nil, err
	}

	config = &EncryptionConfig{
		MsgType: msgType,
	}

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

		// FALL THROUGH
	}

	// Header fully verified :ok_hand:

	isLastChunk := false
	noncePlusEncryptedChunkPlusHash := make([]byte, EncryptChunkLength+DecryptChunkOverhead)
	for true {
		n, err = cipherFile.Read(noncePlusEncryptedChunkPlusHash)
		if err != nil && err != io.EOF {
			return config, err
		}

		if n == 0 {
			break
		}

		isLastPlusDecryptedChunk, err := DecryptAndVerifyChunk(noncePlusEncryptedChunkPlusHash[:n], key, blake)
		if err != nil {
			return config, err
		}

		isLastChunk = IsLastChunkByte(isLastPlusDecryptedChunk[0])

		_, err = plainFile.Write(isLastPlusDecryptedChunk[1:])
		if err != nil {
			return config, err
		}

		if isLastChunk {
			break
		}
	}

	// TODO: Consider turning this into an error
	if !isLastChunk {
		fmt.Fprintf(os.Stderr, "The file just decrypted may have been truncated! Or it could be a bug in the code that did the encryption; that's all we know.\n")
	}

	return config, nil
}

func DecryptAndVerifyChunk(noncePlusEncryptedChunkPlusHash []byte, key *[ValidKeyLength]byte, blake hash.Hash) ([]byte, error) {
	if len(noncePlusEncryptedChunkPlusHash) <= NonceCryptoBlakeOverhead {
		return nil, ErrInvalidChunkLength
	}

	nonce, err := ConvertNonce(noncePlusEncryptedChunkPlusHash[:NonceLength])
	if err != nil {
		return nil, err
	}
	cipher := noncePlusEncryptedChunkPlusHash[NonceLength : len(noncePlusEncryptedChunkPlusHash)-Blake2bHashLength]
	gotBlakeHash := noncePlusEncryptedChunkPlusHash[len(noncePlusEncryptedChunkPlusHash)-Blake2bHashLength:]

	plain, ok := secretbox.Open(nil, cipher, nonce, key)
	if !ok {
		return nil, ErrChunkDecryptionFailed
	}

	blake.Write(noncePlusEncryptedChunkPlusHash[:NonceLength])
	blake.Write(cipher)

	blakeSum := blake.Sum(nil)

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

func IsLastChunkByte(isLastChunk byte) bool {
	// TODO: Make more dynamic and harder to guess
	return isLastChunk == 1
}

func MustDeriveKeypairFromUserInput(requirePassphrase bool) *taber.Keys {
	fmt.Print("Email (optional): ")
	email := MustGetFromStdinStripped()

	if requirePassphrase {
		fmt.Print("Passphrase: ")
	} else {
		fmt.Print("Passphrase (leave blank to generate new, random passphrase): ")
	}
	passphrase := MustGetFromStdinSecure()

	if len(passphrase) == 0 {
		if requirePassphrase {
			exit(fmt.Errorf("Passphrase required but not provided"))
		}

		fmt.Println("Generating random passphrase...")
		var err error
		passphrase, err = RandomPassphrase(25)
		if err != nil {
			exit(err)
		}

		fmt.Printf("Passphrase: %s\n", passphrase)
	}

	if len(email) == 0 {
		email = EmailFromPassphrase(passphrase)
	}

	keypair, err := taber.FromEmailAndPassphrase(email, passphrase)
	if err != nil {
		exit(err)
	}

	return keypair
}
