package cmd

import (
	"fmt"

	authz0 "github.com/hahwul/authz0/pkg/authz0"
	"github.com/spf13/cobra"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(authz0.VERSION)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
