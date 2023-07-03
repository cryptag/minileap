package cmd

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/cryptag/go-minilock/taber"
	"github.com/cryptag/minileap"
	"github.com/spf13/cobra"
)

var encryptTextCmd = &cobra.Command{
	Use:     "encrypt-text",
	Aliases: []string{"et"},
	Short:   "Encrypt the given text with the given email/passphrase combination",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Usage()
			os.Exit(1)
		}

		// assert len(args) == 1

		if args[0] == "" {
			fmt.Fprintf(os.Stderr, "Must specify non-empty string to encrypt\n")
			cmd.Usage()
			os.Exit(1)
		}

		if options.EncryptText_OutputFilename == "" {
			fmt.Fprintf(os.Stderr, "Must specify output filename: `-o <filename>`\n")
			cmd.Usage()
			os.Exit(1)
		}

		cipherFilename := options.EncryptText_OutputFilename
		text := []byte(args[0])

		if bytes.Equal(text, []byte("-")) {
			b, err := ioutil.ReadAll(os.Stdin)
			if err != nil {
				exit(fmt.Errorf("Error reading text from stdin: %s", err))
			}

			// Set global-ish var
			text = b

			// TODO: Probably ensure len(text) <= 10000
		}

		// Derive keypair from user-specified email and password

		requirePassphrase := false
		ident := minileap.MustDeriveIdentityFromUserInput(
			requirePassphrase,
			options.EncryptText_Email,
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

		fmt.Fprintf(os.Stderr, "Using account ID %s to derive symmetric key"+
			" to encrypt text `%s` ...\n", accountID, text)

		exists, err := minileap.FileExists(cipherFilename)
		if err != nil {
			exit(err)
		}
		if exists && !options.EncryptText_ForceOverwrite {
			exit(fmt.Errorf("Desired output file `%s` already exists and"+
				" you've chosen not to overwrite existing files!",
				cipherFilename))
		}

		// Set global-ish var
		cipherFile, err := os.Create(cipherFilename)
		if err != nil {
			exit(err)
		}

		defer cipherFile.Close()

		err = minileap.EncryptReaderToWriter(
			minileap.MessageTypeText,
			bytes.NewReader(text),
			keyPairPrivate32,
			cipherFile,
			nil,
		)
		if err != nil {
			exit(err)
		}

		fmt.Fprintf(os.Stderr, "Encrypted text successfully saved to file `%s`\n",
			cipherFilename)
	},
}
