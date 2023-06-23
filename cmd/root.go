package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "ml",
	Short: "miniLeap: The last encryption utility you'll ever need",
	Long: `miniLeap: The last encryption utility you'll ever need.

Combines the best of libsodium, miniLock, and LeapChat into one simple yet flexible library and command line tool.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Welcome to miniLeap! The last encryption utility you'll ever need.\n\n")

		cmd.Usage()
	},
}

type cliOptions struct {
	EncryptFile_OutputFilename string
	EncryptFile_ForceOverwrite bool
	EncryptFile_Email          string

	DecryptFile_DestinationDirectory string
	DecryptFile_ForceOverwrite       bool
	DecryptFile_Email                string

	EncryptText_OutputFilename string
	EncryptText_ForceOverwrite bool
	EncryptText_Email          string
}

// ~Global vars that cobra ~forces us to have
var (
	options = cliOptions{}
)

func Execute() {
	//
	// encrypt-file
	//
	encryptFileCmd.Flags().StringVarP(&options.EncryptFile_OutputFilename, "output", "o", "", "output filename")
	encryptFileCmd.Flags().BoolVar(&options.EncryptFile_ForceOverwrite, "force", false, "force overwrite of output file?")
	encryptFileCmd.Flags().StringVar(&options.EncryptFile_Email, "email", "", "email to use for key derivation (optional)")
	rootCmd.AddCommand(encryptFileCmd)

	//
	// decrypt-file
	//
	decryptFileCmd.Flags().StringVarP(&options.DecryptFile_DestinationDirectory, "dest", "d", ".", "destination directory (set to '-' to write to stdout)")
	decryptFileCmd.Flags().BoolVar(&options.DecryptFile_ForceOverwrite, "force", false, "force overwrite of output file?")
	decryptFileCmd.Flags().StringVar(&options.DecryptFile_Email, "email", "", "email to use for key derivation (optional)")
	rootCmd.AddCommand(decryptFileCmd)

	//
	// encrypt-text
	//
	encryptTextCmd.Flags().StringVarP(&options.EncryptText_OutputFilename, "output", "o", "", "output filename")
	encryptTextCmd.Flags().BoolVar(&options.EncryptText_ForceOverwrite, "force", false, "force overwrite of output file?")
	encryptTextCmd.Flags().StringVar(&options.EncryptText_Email, "email", "", "email to use for key derivation (optional)")
	rootCmd.AddCommand(encryptTextCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
