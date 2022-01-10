package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// setRoleCmd represents the setRole command
var setRoleCmd = &cobra.Command{
	Use:   "setRole",
	Short: "Append Role to Template",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("setRole called")
	},
}

func init() {
	rootCmd.AddCommand(setRoleCmd)
}
