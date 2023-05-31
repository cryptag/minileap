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

// Global vars that cobra ~forces us to have
var (
	gEncryptFile_OutputFilename string
	gEncryptFile_ForceOverwrite bool

	gDecryptFile_OutputFilename string
	gDecryptFile_ForceOverwrite bool
)

func Execute() {
	//
	// encrypt-file
	//
	encryptFileCmd.Flags().BoolVar(&gEncryptFile_ForceOverwrite, "force", false, "force overwrite of output file?")
	encryptFileCmd.Flags().StringVarP(&gEncryptFile_OutputFilename, "output", "o", "", "output filename")
	rootCmd.AddCommand(encryptFileCmd)

	//
	// decrypt-file
	//
	decryptFileCmd.Flags().BoolVar(&gDecryptFile_ForceOverwrite, "force", false, "force overwrite of output file?")
	decryptFileCmd.Flags().StringVarP(&gDecryptFile_OutputFilename, "output", "o", "", "output filename")
	rootCmd.AddCommand(decryptFileCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
