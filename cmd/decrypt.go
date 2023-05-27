package cmd

import (
	"crypto/sha512"
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
	rootCmd.AddCommand(decryptCmd)
}

var decryptCmd = &cobra.Command{
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

		// Save decrypted file with ".enc" extension removed
		plainFilename := filename[:len(filename)-len(".enc")]
		if !strings.HasSuffix(filename, ".enc") {
			// ...or with ".dec" extension appended
			plainFilename = filename + ".dec"
		}

		if fileExists(plainFilename) {
			exit(fmt.Errorf("Cannot save new file `%s`; file already exists at that location", plainFilename))
		}

		plainFile, err := os.Create(plainFilename)
		if err != nil {
			exit(err)
		}
		defer plainFile.Close()

		// Hashers ftw
		blake, err := blake2b.New512(KeyPair.Private)
		if err != nil {
			exit(err)
		}
		sha512Append := sha512.New()
		sha512Append.Write(KeyPair.Private)

		// TODO: Expect the filename in the first non-header chunk,
		// padded to 255 bytes.  Make the first byte specify the
		// length of the filename if needed, thus resulting in the
		// first non-header chunk size being 256 bytes.

		//
		// Header: Decrypt it, verify its hash
		//

		var n int
		noncePlusEncryptedHeaderPlusHash := make([]byte, DecryptHeaderLength)

		n, err = cipherFile.Read(noncePlusEncryptedHeaderPlusHash)
		if err != nil {
			exit(err)
		}

		if n != DecryptHeaderLength {
			exit(fmt.Errorf("Decrypting header: Wanted %v bytes, got %v\n",
				DecryptHeaderLength, n))
		}

		// noncePlusEncryptedHeaderWithoutHash := noncePlusEncryptedHeaderPlusHash[:len(noncePlusEncryptedHeaderPlusHash)-Blake2bHashLength]
		// headerHash := noncePlusEncryptedHeaderPlusHash[len(noncePlusEncryptedHeaderPlusHash)-Blake2bHashLength:]

		// blake.Write(noncePlusEncryptedHeaderWithoutHash)

		// blakeHeaderSum := blake.Sum(nil)

		// if subtle.ConstantTimeCompare(headerHash, blakeHeaderSum) == 0 {
		// 	exit(fmt.Errorf("Header verification failed; Blake2b checksum is incorrect; got %v, wanted %v\n", headerHash, blakeHeaderSum))
		// }

		// Header Blake2s hash verification: successful! :tada:

		// blake.Write(blakeHeaderSum)

		// fmt.Printf("About to run DecryptAndVerifyChunk(...) on header\n")

		header, err := DecryptAndVerifyChunk(noncePlusEncryptedHeaderPlusHash, KeyPairPrivate32, blake)
		if err != nil {
			exit(err)
		}

		fmt.Printf("\n  !!! DecryptAndVerifyChunk(header) WORKED\n\n")

		// fmt.Printf("About to run ParseDecryptedHeaderIntoValidFields(...)\n")

		chunkSize, msgType, err := ParseDecryptedHeaderIntoValidFields(header)
		if err != nil {
			exit(err)
		}

		fmt.Printf("chunkSize == %v\n", chunkSize)
		fmt.Printf("msgType   == %v\n", msgType)

		if msgType != MessageTypeFileWithFilename {
			exit(fmt.Errorf("TEMPORARY: Got msgType == %v, wanted %v\n",
				msgType, MessageTypeFileWithFilename))
		}

		// Header fully verified :ok_hand:

		sha512Append.Write(noncePlusEncryptedHeaderPlusHash)

		var sha512Wanted []byte
		noncePlusEncryptedChunkPlusHash := make([]byte, chunkSize+TotalChunkOverhead)
		for i := 0; true; i++ {
			n, err = cipherFile.Read(noncePlusEncryptedChunkPlusHash)
			if err != nil && err != io.EOF {
				exit(err)
			}

			if n == 0 {
				break
			}

			fmt.Printf("Read %v bytes into noncePlusEncryptedChunkPlusHash\n", n)

			if n == Sha512HashLength {
				sha512Wanted = noncePlusEncryptedChunkPlusHash[:n]
				break
			}

			// Sha512HashLength < MinChunkLength, so we need not more checks

			// TODO: Error out if `n < Sha512HashLength && n < chunkSize`?

			endOfFile := (err == io.EOF)

			fmt.Printf("endOfFile == %v\n", endOfFile)

			if i == 0 && n < chunkSize {
				// One-chunk message!
				fmt.Printf("Special case: one-chunk message; n == %v\n", n)

				nonceChunkHash := noncePlusEncryptedChunkPlusHash[:n]

				fmt.Printf("\nnonceChunkHash full (%v bytes):\n    %v\n\n", len(nonceChunkHash), nonceChunkHash)
				fmt.Printf("nonceChunkHash minus ending (%v bytes):\n    %v\n\n", len(nonceChunkHash[:len(nonceChunkHash)-Sha512HashLength]), nonceChunkHash[:len(nonceChunkHash)-Sha512HashLength])
				fmt.Printf("Therefore, last 64 bytes (actually %v):\n    %v\n\n", len(nonceChunkHash[len(nonceChunkHash)-Sha512HashLength:]), nonceChunkHash[len(nonceChunkHash)-Sha512HashLength:])

				decryptedChunk, err := DecryptAndVerifyChunk(nonceChunkHash[:len(nonceChunkHash)-Sha512HashLength], KeyPairPrivate32, blake)
				if err != nil {
					exit(err)
				}

				fmt.Printf("decryptedChunk == `%s`\n", decryptedChunk)

				_, err = plainFile.Write(decryptedChunk)
				if err != nil {
					exit(err)
				}

				sha512Append.Write(nonceChunkHash[:len(nonceChunkHash)-Sha512HashLength])
				sha512Wanted = nonceChunkHash[len(nonceChunkHash)-Sha512HashLength:]

				break
			}

			fmt.Printf("  !!! PAST the special case!\n")

			decryptedChunk, err := DecryptAndVerifyChunk(noncePlusEncryptedChunkPlusHash[:n], KeyPairPrivate32, blake)
			if err != nil {
				exit(err)
			}

			_, err = plainFile.Write(decryptedChunk)
			if err != nil {
				exit(err)
			}

			sha512Append.Write(noncePlusEncryptedChunkPlusHash[:n])

			if endOfFile {
				break
			}
		}

		fmt.Printf("\nsha512Wanted == %v\n\n", sha512Wanted)

		// Verify final hash
		sha512AppendSum := sha512Append.Sum(nil)
		if subtle.ConstantTimeCompare(sha512Wanted, sha512AppendSum) == 0 {
			// TODO: Clean up properly (e.g., delete tampered-with
			// file, `plainFile`)
			exit(fmt.Errorf("Everything decrypted perfectly, all the Blake2b chunk hashes were legit, but the final SHA-512 hash doesn't match! Wanted %v , got %v", sha512Wanted, sha512AppendSum))
		}

		fmt.Printf("Decrypted file successfully saved to %s\n", plainFilename)
	},
}

// func DecryptAndVerifyHeader(noncePlusEncryptedHeaderPlusHash []byte, key *[ValidKeyLength]byte, blake hash.Hash) ([]byte, error) {
// 	headerb, err := DecryptAndVerifyChunk(noncePlusEncryptedHeaderPlusHash, key, blake)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return header, nil
// }

func DecryptAndVerifyChunk(noncePlusEncryptedChunkPlusHash []byte, key *[ValidKeyLength]byte, blake hash.Hash) ([]byte, error) {
	if len(noncePlusEncryptedChunkPlusHash) <= TotalChunkOverhead {
		fmt.Printf("DecryptAndVerifyChunk: len(noncePlusEncryptedChunkPlusHash) == %v\n", len(noncePlusEncryptedChunkPlusHash))
		return nil, ErrInvalidChunkLength
	}

	fmt.Printf("\nDecryptAndVerifyChunk: noncePlusEncryptedChunkPlusHash length %v:\n    %v\n\n", len(noncePlusEncryptedChunkPlusHash), noncePlusEncryptedChunkPlusHash)

	nonce, err := ConvertNonce(noncePlusEncryptedChunkPlusHash[:NonceLength])
	if err != nil {
		return nil, err
	}
	cipher := noncePlusEncryptedChunkPlusHash[NonceLength : len(noncePlusEncryptedChunkPlusHash)-Blake2bHashLength]
	gotBlakeHash := noncePlusEncryptedChunkPlusHash[len(noncePlusEncryptedChunkPlusHash)-Blake2bHashLength:]

	// fmt.Printf("len(nonce) == %v, %v\n", len(nonce), nonce)
	fmt.Printf("len(cipher) == %v:\n    %v\n\n", len(cipher), cipher)
	fmt.Printf("len(gotBlakeHash) == %v\n", len(gotBlakeHash))

	plain, ok := secretbox.Open(nil, cipher, nonce, key)
	if !ok {
		fmt.Printf("Decryption failed :-(\n")
		return nil, ErrChunkDecryptionFailed
	}

	blake.Write(noncePlusEncryptedChunkPlusHash[:NonceLength])
	blake.Write(cipher)

	blakeSum := blake.Sum(nil)

	if subtle.ConstantTimeCompare(gotBlakeHash, blakeSum) == 0 {
		fmt.Printf("gotBlakeHash length %v == %v\n", len(gotBlakeHash), gotBlakeHash)
		fmt.Printf("blakeSum length     %v == %v\n", len(blakeSum), blakeSum)
		return nil, ErrInvalidChunkHash
	}

	blake.Write(blakeSum)

	fmt.Printf("DecryptAndVerifyChunk: decrypted plain == %v\n", plain)

	return plain, nil
}

func ParseDecryptedHeaderIntoValidFields(headerb []byte) (chunkSize int, msgType int16, err error) {
	if len(headerb) != EncryptHeaderLength {
		err = fmt.Errorf("Decrypted header is %v bytes, expected %v\n", len(headerb), EncryptHeaderLength)
		return
	}

	chunkSize32 := int32(headerb[0])<<24 | int32(headerb[1])<<16 | int32(headerb[2])<<8 | int32(headerb[3])
	msgType = int16(headerb[4])<<8 | int16(headerb[5])

	if chunkSize32 < MinChunkLength {
		err = fmt.Errorf("Refusing to decrypt; chunk size is %v, which is below the minimum of %v\n", chunkSize, MinChunkLength)
		return
	}

	chunkSize = int(chunkSize32)

	if msgType == MessageTypeZero {
		err = ErrInvalidMessageType
		return
	}

	return
}

func MustDeriveKeypairFromUserInput() *taber.Keys {

	//
	// !!! FIXME/TODO/UNFUCKME TEMPORARY !!!
	//

	return &taber.Keys{
		Private: []uint8{0x30, 0x1c, 0xfb, 0x4, 0x3c, 0x22, 0xc3, 0xe4, 0x58, 0x1c, 0x43, 0xcc, 0x44, 0xab, 0x9c, 0x1c, 0xd3, 0x59, 0xee, 0x7e, 0x33, 0x2b, 0x52, 0x2a, 0x2f, 0xc, 0x8c, 0xff, 0xb7, 0x6d, 0xd4, 0x7c},
		Public:  []uint8{0x5c, 0xa2, 0xc1, 0xc3, 0x8d, 0x7b, 0xaa, 0xc2, 0xfa, 0xc0, 0x89, 0xd5, 0x74, 0xc7, 0x4, 0xe4, 0xc7, 0x24, 0xf3, 0x7c, 0xa3, 0x5e, 0xef, 0x3d, 0x16, 0x72, 0x96, 0x90, 0xaa, 0x8e, 0xd, 0x6},
	}

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

	fmt.Printf("%#v\n", keypair)

	return keypair
}
