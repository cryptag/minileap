package cmd

import (
	"fmt"
	"os"

	"github.com/cryptag/minileap"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(encryptFileCmd)
}

var encryptFileCmd = &cobra.Command{
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

		keyPair := minileap.MustDeriveKeypairFromUserInput()

		keyPairPrivate32, err := minileap.ConvertKey(keyPair.Private)
		if err != nil {
			exit(err)
		}

		defer minileap.MustWipeKeys(keyPair, keyPairPrivate32)

		mID, err := keyPair.EncodeID()
		if err != nil {
			exit(err)
		}

		fmt.Printf("Using miniLock ID %s to derive symmetric key to encrypt file %s ...\n", mID, filename)

		cipherFilename, err := minileap.EncryptFile(filename, keyPairPrivate32, "", false)
		if err != nil {
			exit(err)
		}

		fmt.Printf("File successfully encrypted and saved to %s\n", cipherFilename)
	},
}

// From https://www.tutorialspoint.com/how-to-check-if-a-file-exists-in-golang
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func exit(err error) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	os.Exit(1)
}
