package cmd

import (
	"fmt"
	"os"

	"github.com/cryptag/go-minilock/taber"
	"github.com/cryptag/minileap"
	"github.com/spf13/cobra"
)

var decryptFileCmd = &cobra.Command{
	Use:     "decrypt-file",
	Aliases: []string{"df"},
	Short:   "Decrypt the given file with the given email/passphrase combination",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Usage()
			os.Exit(1)
		}

		// assert len(args) == 1

		filename := args[0]

		exists, err := minileap.FileExists(filename)
		if err != nil {
			exit(err)
		}

		if !exists {
			exit(fmt.Errorf("File `%s` does not exist and thus cannot be decrypted!", filename))
		}

		// Derive keypair from user-specified email and password

		requirePassphrase := true
		ident := minileap.MustDeriveIdentityFromUserInput(
			requirePassphrase,
			options.DecryptFile_Email,
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

		fmt.Fprintf(os.Stderr, "Using account ID %s to derive symmetric key to decrypt file `%s` ...\n",
			accountID, filename)

		config, err := minileap.DecryptFile(filename, keyPairPrivate32, options.DecryptFile_DestinationDirectory, options.DecryptFile_ForceOverwrite)
		if err != nil {
			exit(err)
		}

		if config.OrigFilename == "" {
			// Just decrypted a file of message type non-file and
			// wrote it to stdout
			fmt.Fprintf(os.Stderr, "File with underlying message type %v successfully decrypted",
				minileap.MessageTypeName(config.MsgType))
		} else if options.DecryptFile_DestinationDirectory != "-" {
			// Just decrypted a file of MessageTypeFileWithFilename
			fmt.Fprintf(os.Stderr, "Decrypted file successfully saved to `%s`\n",
				config.SavedAs())
		}
	},
}
