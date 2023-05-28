package cmd

import (
	"crypto/subtle"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"

	"github.com/cryptag/go-minilock/taber"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/nacl/secretbox"
)

func init() {
	rootCmd.AddCommand(decryptFileCmd)
}

var decryptFileCmd = &cobra.Command{
	Use:   "decrypt-file",
	Short: "Decrypt the given file with the given email/passphrase combination",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			exit(fmt.Errorf("Usage: minileap decrypt <filename>"))
		}

		// assert len(args) == 1

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

		// Use not-so-fancy crypto to decrypt with user keypair

		fmt.Printf("Using miniLock ID %s to derive symmetric key to decrypt file %s ...\n", mID, filename)

		cipherFile, err := os.Open(filename)
		if err != nil {
			exit(err)
		}
		defer cipherFile.Close()

		// TODO: Make the name and location of resulting decrypted
		// file configurable with `-o <outfile>` option or similar

		// Save decrypted file with ".minileap" extension removed
		plainFilename := filename[:len(filename)-len(".minileap")]
		if fileExists(plainFilename) || !strings.HasSuffix(filename, ".minileap") {
			// ...or with ".dec" extension appended
			plainFilename = filename + ".dec"
		}

		plainFile, err := os.Create(plainFilename)
		if err != nil {
			exit(err)
		}
		defer plainFile.Close()

		// TODO: Run `os.Remove(plainFilename)` on error

		// Hashers ftw
		blake, err := blake2b.New512(KeyPair.Private)
		if err != nil {
			exit(err)
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
			exit(err)
		}

		if n != DecryptHeaderLength {
			exit(fmt.Errorf("Decrypting header: Wanted %v bytes, got %v\n",
				DecryptHeaderLength, n))
		}

		header, err := DecryptAndVerifyChunk(noncePlusEncryptedHeaderPlusHash, KeyPairPrivate32, blake)
		if err != nil {
			exit(err)
		}

		chunkSize, msgType, err := ParseDecryptedHeaderIntoValidFields(header)
		if err != nil {
			exit(err)
		}

		if msgType != MessageTypeFileWithFilename {
			exit(fmt.Errorf("TEMPORARY: Got msgType == %v, wanted %v\n",
				msgType, MessageTypeFileWithFilename))
		}

		// Header fully verified :ok_hand:

		isLastChunk := false
		noncePlusEncryptedChunkPlusHash := make([]byte, chunkSize+DecryptChunkOverhead)
		for true {
			n, err = cipherFile.Read(noncePlusEncryptedChunkPlusHash)
			if err != nil && err != io.EOF {
				exit(err)
			}

			if n == 0 {
				break
			}

			isLastPlusDecryptedChunk, err := DecryptAndVerifyChunk(noncePlusEncryptedChunkPlusHash[:n], KeyPairPrivate32, blake)
			if err != nil {
				exit(err)
			}

			isLastChunk = IsLastChunkByte(isLastPlusDecryptedChunk[0])

			_, err = plainFile.Write(isLastPlusDecryptedChunk[1:])
			if err != nil {
				exit(err)
			}

			if isLastChunk {
				break
			}
		}

		if !isLastChunk {
			fmt.Fprintf(os.Stderr, "The file just decrypted may have been truncated! Or it could be a bug in the code that did the encryption; that's all we know.\n")
		}

		fmt.Printf("Decrypted file successfully saved to %s\n", plainFilename)
	},
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

func MustDeriveKeypairFromUserInput() *taber.Keys {
	fmt.Print("Email (optional): ")
	email := MustGetFromStdinStripped()

	fmt.Print("Passphrase (leave blank to generate new, random passphrase): ")
	passphrase := MustGetFromStdinSecure()

	if len(passphrase) == 0 {
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
