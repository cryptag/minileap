package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(serveCmd)
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("TODO: serve\n")
	},
}
