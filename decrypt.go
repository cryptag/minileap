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

	if FileExists(plainFilename) && !forceOverwrite {
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

	err = DecryptReaderToWriter(cipherFile, key, plainFile)
	if err != nil {
		return plainFilename, err
	}

	return plainFilename, nil
}

func DecryptReaderToWriter(cipherFile io.Reader, key *[32]byte, plainFile io.Writer) error {
	// TODO: Run `os.Remove(plainFilename)` on error

	// Hashers ftw
	blake, err := blake2b.New512((*key)[:])
	if err != nil {
		return err
	}

	// TODO: Expect the filename in the first non-header chunk,
	// padded to 255 bytes.  Make the first byte specify the
	// length of the filename if needed, thus resulting in the
	// first non-header chunk size being 256 bytes.

	//
	// Header: Decrypt it, verify its hash
	//

	noncePlusEncryptedHeaderPlusHash := make([]byte, DecryptHeaderLength)

	n, err := cipherFile.Read(noncePlusEncryptedHeaderPlusHash)
	if err != nil {
		return err
	}

	if n != DecryptHeaderLength {
		return fmt.Errorf("Decrypting header: Wanted %v bytes, got %v\n",
			DecryptHeaderLength, n)
	}

	header, err := DecryptAndVerifyChunk(noncePlusEncryptedHeaderPlusHash, key, blake)
	if err != nil {
		return err
	}

	msgType, err := ParseDecryptedHeaderIntoValidFields(header)
	if err != nil {
		return err
	}

	if msgType != MessageTypeFileWithFilename {
		return fmt.Errorf("TEMPORARY: Got msgType == %v, wanted %v\n",
			msgType, MessageTypeFileWithFilename)
	}

	// Header fully verified :ok_hand:

	isLastChunk := false
	noncePlusEncryptedChunkPlusHash := make([]byte, EncryptChunkLength+DecryptChunkOverhead)
	for true {
		n, err = cipherFile.Read(noncePlusEncryptedChunkPlusHash)
		if err != nil && err != io.EOF {
			return err
		}

		if n == 0 {
			break
		}

		isLastPlusDecryptedChunk, err := DecryptAndVerifyChunk(noncePlusEncryptedChunkPlusHash[:n], key, blake)
		if err != nil {
			return err
		}

		isLastChunk = IsLastChunkByte(isLastPlusDecryptedChunk[0])

		_, err = plainFile.Write(isLastPlusDecryptedChunk[1:])
		if err != nil {
			return err
		}

		if isLastChunk {
			break
		}
	}

	if !isLastChunk {
		fmt.Fprintf(os.Stderr, "The file just decrypted may have been truncated! Or it could be a bug in the code that did the encryption; that's all we know.\n")
	}

	return nil
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
