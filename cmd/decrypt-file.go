package cmd

import (
	"fmt"

	"github.com/cryptag/minileap"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(decryptFileCmd)
}

var decryptFileCmd = &cobra.Command{
	Use:   "decrypt-file",
	Short: "Decrypt the given file with the given email/passphrase combination",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			exit(fmt.Errorf("Usage: ml decrypt <filename>"))
		}

		// assert len(args) == 1

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

		fmt.Printf("Using miniLock ID %s to derive symmetric key to decrypt file %s ...\n", mID, filename)

		plainFilename, err := minileap.DecryptFile(filename, keyPairPrivate32, "", false)
		if err != nil {
			exit(err)
		}

		fmt.Printf("Decrypted file successfully saved to `%s`\n", plainFilename)
	},
}
