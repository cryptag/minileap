package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cryptag/sodium"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
)

func init() {
	rootCmd.AddCommand(encryptCmd)
}

const (
	// We encrypt 1mb chunks
	PUSH_MESSAGE_SIZE = 1_000_000

	// PULL_MESSAGE_SIZE = PUSH_MESSAGE_SIZE + sodium.CryptoSecretStreamXChaCha20Poly1305ABytes
	PULL_MESSAGE_SIZE = PUSH_MESSAGE_SIZE + 17
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt the given file with the given email/passphrase combination",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			exit(fmt.Errorf("Usage: minileap encrypt <filename>"))
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

		// Use fancy crypto to encrypt with user keypair

		fmt.Printf("Using miniLock ID %s to encrypt file %s ...\n", mID, filename)

		// Create new XChaCha20-Poly1305 key based on the private key
		// derived above
		xcpKey := sodium.SecretStreamXCPKey{
			Bytes: keypair.Private,
		}

		plainFile, err := os.Open(filename)
		if err != nil {
			exit(err)
		}
		defer plainFile.Close()

		plainFileInfo, err := plainFile.Stat()
		if err != nil {
			exit(err)
		}
		plainFileLength := plainFileInfo.Size()

		// TODO: Make the name and location of resulting encrypted
		// file configurable with `-o <outfile>` option or similar

		// Save encrypted file with ".enc" extension appended
		cipherFilename := filename + ".enc"
		cipherFile, err := os.Create(cipherFilename)
		if err != nil {
			exit(err)
		}
		defer cipherFile.Close()

		// encoder, err := sodium.MakeSecretStreamXCPEncoder(xcpKey, cipherFile)
		// if err != nil {
		// 	exit(err)
		// }
		encoder := sodium.MakeSecretStreamXCPEncoder(xcpKey, cipherFile)

		// TODO: Add the filename in the first chunk, padded to 255
		// bytes.  Make the first byte specify the length of the
		// filename if needed, thus resulting in the first message
		// size being 256 bytes.

		numChunks := NumPushChunks(plainFileLength)

		var n int
		var b [PUSH_MESSAGE_SIZE]byte
		for i := int64(0); i < numChunks-1; i++ {
			n, err = plainFile.Read(b[:])
			if err != nil {
				exit(err)
			}

			encoder.SetTag(sodium.SecretStreamTag_Push)

			_, err = encoder.Write(b[:n])
			if err != nil {
				exit(err)
			}
		}

		// Write final chunk
		n, err = plainFile.Read(b[:])
		if err != nil && err != io.EOF {
			exit(err)
		}

		encoder.SetTag(sodium.SecretStreamTag_Final)
		_, err = encoder.WriteAndClose(b[:n])
		if err != nil {
			exit(err)
		}

		fmt.Printf("Encrypted file successfully saved to %s\n", cipherFilename)
	},
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

func NumPushChunks(fileLength int64) int64 {
	chunks := fileLength / PUSH_MESSAGE_SIZE
	if fileLength%PUSH_MESSAGE_SIZE > 0 {
		chunks++
	}

	return chunks
}

func NumPullChunks(fileLength int64) int64 {
	chunks := fileLength / PULL_MESSAGE_SIZE
	if fileLength%PULL_MESSAGE_SIZE > 0 {
		chunks++
	}

	return chunks
}
