package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "minileap",
	Short: "miniLeap: The last encryption utility you'll ever need",
	Long: `miniLeap: The last encryption utility you'll ever need.

Combines the best of libsodium, miniLock, and LeapChat into one simple yet flexible utility`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("TODO: Add actual functionality\n")
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
