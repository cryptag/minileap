package cmd

import (
	"fmt"
	"os"

	"github.com/cryptag/minileap"
	"github.com/spf13/cobra"
)

var encryptFileCmd = &cobra.Command{
	Use:     "encrypt-file",
	Aliases: []string{"ef"},
	Short:   "Encrypt the given file with the given email/passphrase combination",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			exit(fmt.Errorf("Usage: ml encrypt-file <filename> [ <filename2> ... ]"))
		}

		// assert len(args) >= 1

		// TODO: Loop over all files listed
		filename := args[0]

		if !minileap.FileExists(filename) {
			exit(fmt.Errorf("File `%s` does not exist and thus cannot be encrypted!", filename))
		}

		// Derive keypair from user-specified email and password

		requirePassphrase := false
		keyPair := minileap.MustDeriveKeypairFromUserInput(requirePassphrase)

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

		cipherFilename, err := minileap.EncryptFile(filename, keyPairPrivate32, gEncryptFile_OutputFilename, gEncryptFile_ForceOverwrite)
		if err != nil {
			exit(err)
		}

		fmt.Printf("Encrypted file successfully saved to `%s`\n", cipherFilename)
	},
}

func exit(err error) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	os.Exit(1)
}
