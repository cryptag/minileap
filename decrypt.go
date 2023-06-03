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

func DecryptFile(filename string, key *[32]byte, dest string, forceOverwrite bool) (plainFilename string, err error) {
	if key == nil || *key == [32]byte{} {
		return "", ErrInvalidKey
	}

	// TODO: Make the name and location of resulting decrypted
	// file configurable with `-o <outfile>` option or similar

	if strings.HasSuffix(filename, MiniLeapFileExtensionIncludingDot) {
		// Save decrypted file with `.minileap` extension removed...
		plainFilename = filename[:len(filename)-len(MiniLeapFileExtensionIncludingDot)]
	}

	if plainFilename == "" {
		plainFilename = filename + ".dec"
	}

	// Prepend destination dir to `plainFilename`
	sep := string(filepath.Separator)
	plainFilename = strings.TrimRight(dest, sep) + sep + filepath.Base(plainFilename)

	if FileExists(plainFilename) && !forceOverwrite {
		return plainFilename, fmt.Errorf("Unencrypted file `%s` already exists and you've chosen not to overwrite existing files!", plainFilename)
	}

	cipherFile, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer cipherFile.Close()

	plainFile, err := os.Create(plainFilename)
	if err != nil {
		return plainFilename, err
	}
	defer plainFile.Close()

	// TODO: Run `os.Remove(plainFilename)` on error

	// Hashers ftw
	blake, err := blake2b.New512((*key)[:])
	if err != nil {
		return plainFilename, err
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
		return plainFilename, err
	}

	if n != DecryptHeaderLength {
		return plainFilename, fmt.Errorf("Decrypting header: Wanted %v bytes, got %v\n",
			DecryptHeaderLength, n)
	}

	header, err := DecryptAndVerifyChunk(noncePlusEncryptedHeaderPlusHash, key, blake)
	if err != nil {
		return plainFilename, err
	}

	chunkSize, msgType, err := ParseDecryptedHeaderIntoValidFields(header)
	if err != nil {
		return plainFilename, err
	}

	if msgType != MessageTypeFileWithFilename {
		return plainFilename, fmt.Errorf("TEMPORARY: Got msgType == %v, wanted %v\n",
			msgType, MessageTypeFileWithFilename)
	}

	// Header fully verified :ok_hand:

	isLastChunk := false
	noncePlusEncryptedChunkPlusHash := make([]byte, chunkSize+DecryptChunkOverhead)
	for true {
		n, err = cipherFile.Read(noncePlusEncryptedChunkPlusHash)
		if err != nil && err != io.EOF {
			return plainFilename, err
		}

		if n == 0 {
			break
		}

		isLastPlusDecryptedChunk, err := DecryptAndVerifyChunk(noncePlusEncryptedChunkPlusHash[:n], key, blake)
		if err != nil {
			return plainFilename, err
		}

		isLastChunk = IsLastChunkByte(isLastPlusDecryptedChunk[0])

		_, err = plainFile.Write(isLastPlusDecryptedChunk[1:])
		if err != nil {
			return plainFilename, err
		}

		if isLastChunk {
			break
		}
	}

	if !isLastChunk {
		fmt.Fprintf(os.Stderr, "The file just decrypted may have been truncated! Or it could be a bug in the code that did the encryption; that's all we know.\n")
	}

	return plainFilename, nil
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

func ParseDecryptedHeaderIntoValidFields(headerb []byte) (chunkSize int, msgType uint16, err error) {
	if len(headerb) != EncryptHeaderLength {
		err = fmt.Errorf("Decrypted header is %v bytes, expected %v\n", len(headerb), EncryptHeaderLength)
		return
	}

	// Can't overflow on a 32-bit system because `headerb`'s chunk
	// size is just a uint24, not uint32
	chunkSize = int(headerb[0])<<16 | int(headerb[1])<<8 | int(headerb[2])

	msgType = uint16(headerb[3])<<8 | uint16(headerb[4])

	if chunkSize < MinChunkLength {
		err = fmt.Errorf("Refusing to decrypt; chunk size is %v, which is below the minimum of %v\n", chunkSize, MinChunkLength)
		return
	}

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
