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
		cmd.Usage()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
