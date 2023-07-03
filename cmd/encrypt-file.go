package cmd

import (
	"fmt"
	"os"

	"github.com/cryptag/go-minilock/taber"
	"github.com/cryptag/minileap"
	"github.com/spf13/cobra"
)

var encryptFileCmd = &cobra.Command{
	Use:     "encrypt-file",
	Aliases: []string{"ef"},
	Short:   "Encrypt the given file with the given email/passphrase combination",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Usage()
			os.Exit(1)
		}

		// assert len(args) >= 1

		// TODO: Loop over all files listed
		filename := args[0]

		exists, err := minileap.FileExists(filename)
		if err != nil {
			exit(err)
		}

		if !exists {
			exit(fmt.Errorf("File `%s` does not exist and thus cannot be encrypted!", filename))
		}

		// Derive keypair from user-specified email and password

		requirePassphrase := false
		ident := minileap.MustDeriveIdentityFromUserInput(
			requirePassphrase,
			options.EncryptFile_Email,
		)
		defer ident.Wipe()

		keyPairPrivate32, err := minileap.ConvertKey(ident.Private)
		if err != nil {
			exit(err)
		}
		defer taber.WipeKeyArray(keyPairPrivate32)

		accountID, err := ident.EncodeID()
		if err != nil {
			exit(err)
		}

		fmt.Fprintf(os.Stderr, "Using account ID %s to derive symmetric key to encrypt file `%s` ...\n", accountID, filename)

		cipherFilename, err := minileap.EncryptFile(filename, keyPairPrivate32, options.EncryptFile_OutputFilename, options.EncryptFile_ForceOverwrite)
		if err != nil {
			exit(err)
		}

		fmt.Fprintf(os.Stderr, "Encrypted file successfully saved to `%s`\n", cipherFilename)
	},
}

func exit(err error) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	os.Exit(1)
}
