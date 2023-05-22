package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cryptag/go-minilock/taber"
	"github.com/cryptag/sodium"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(decryptCmd)
}

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt the given file with the given email/passphrase combination",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			exit(fmt.Errorf("Usage: minileap decrypt <filename>"))
		}

		// assert len(args) == 1

		filename := args[0]

		// Derive keypair from user-specified email and password

		keypair := MustDeriveKeypairFromUserInput()
		defer keypair.Wipe()

		mID, err := keypair.EncodeID()
		if err != nil {
			exit(err)
		}

		// Use fancy crypto to decrypt with user keypair

		fmt.Printf("Using miniLock ID %s to decrypt file %s ...\n", mID, filename)

		// Create new XChaCha20-Poly1305 key based on the private key
		// derived above
		xcpKey := sodium.SecretStreamXCPKey{
			Bytes: keypair.Private,
		}

		cipherFile, err := os.Open(filename)
		if err != nil {
			exit(err)
		}
		defer cipherFile.Close()

		cipherFileInfo, err := cipherFile.Stat()
		if err != nil {
			exit(err)
		}
		cipherFileLength := cipherFileInfo.Size()

		// TODO: Make the name and location of resulting decrypted
		// file configurable with `-o <outfile>` option or similar

		// Save decrypted file with ".enc" extension removed
		plainFilename := filename[:len(filename)-len(".enc")]
		if !strings.HasSuffix(filename, ".enc") {
			// ...or with ".dec" extension appended
			plainFilename = filename + ".dec"
		}

		plainFile, err := os.Create(plainFilename)
		if err != nil {
			exit(err)
		}
		defer plainFile.Close()

		// encoder, err := sodium.MakeSecretStreamXCPEncoder(xcpKey, plainFile)
		// if err != nil {
		// 	exit(err)
		// }
		encoder := sodium.MakeSecretStreamXCPEncoder(xcpKey, plainFile)

		decoder, err := sodium.MakeSecretStreamXCPDecoder(xcpKey, cipherFile, encoder.Header())
		if err != nil {
			exit(err)
		}

		// TODO: Add the filename in the first chunk, padded to 255
		// bytes.  Make the first byte specify the length of the
		// filename if needed, thus resulting in the first message
		// size being 256 bytes.

		numChunks := NumPullChunks(cipherFileLength)

		var n int
		var b [PUSH_MESSAGE_SIZE]byte // Yes, push, not pull
		for i := int64(0); i < numChunks-1; i++ {
			n, err = decoder.Read(b[:])
			if err != nil {
				exit(err)
			}

			_, err = plainFile.Write(b[:n])
			if err != nil {
				exit(err)
			}
		}

		// Read final chunk
		n, err = decoder.Read(b[:])
		if err != nil && err != io.EOF {
			exit(err)
		}

		n, err = plainFile.Write(b[:n])
		if err != nil {
			exit(err)
		}

		fmt.Printf("Decrypted file successfully saved to %s\n", plainFilename)
	},
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
