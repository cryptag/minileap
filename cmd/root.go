package cmd

import (
	"fmt"
	"os"

	"github.com/cryptag/minileap"
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
	EncryptFile_ChunkSize      int

	DecryptFile_DestinationDirectory string
	DecryptFile_ForceOverwrite       bool
}

// ~Global vars that cobra ~forces us to have
var (
	options = cliOptions{}
)

func Execute() {
	// TEMPORARY: Set defaults
	options.EncryptFile_ChunkSize = minileap.DefaultEncryptChunkLength

	// TODO: Remove the above and fully implement this instead:
	//
	// encryptFileCmd.Flags().StringVarP(&options.EncryptFile_ChunkSizeStr, "chunk-size", "s", "medium", "chunk size. Options: min (1024), small (65536), default (1_000_000) (default), max (16_777_215), or custom (uint24)")

	//
	// encrypt-file
	//
	encryptFileCmd.Flags().BoolVar(&options.EncryptFile_ForceOverwrite, "force", false, "force overwrite of output file?")
	encryptFileCmd.Flags().StringVarP(&options.EncryptFile_OutputFilename, "output", "o", "", "output filename")
	rootCmd.AddCommand(encryptFileCmd)

	//
	// decrypt-file
	//
	decryptFileCmd.Flags().BoolVar(&options.DecryptFile_ForceOverwrite, "force", false, "force overwrite of output file?")
	decryptFileCmd.Flags().StringVarP(&options.DecryptFile_DestinationDirectory, "dest", "d", ".", "destination directory")
	rootCmd.AddCommand(decryptFileCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
