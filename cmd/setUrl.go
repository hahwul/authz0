package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// setUrlCmd represents the setUrl command
var setUrlCmd = &cobra.Command{
	Use:   "setUrl",
	Short: "Append URL to Template",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("setUrl called")
	},
}

func init() {
	rootCmd.AddCommand(setUrlCmd)
}
