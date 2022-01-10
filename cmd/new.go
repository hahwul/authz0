package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var name string
var includeURLs, includeRoles string
var successStatus string
var failStatus, failRegex string
var failSize int

// newCmd represents the new command
var newCmd = &cobra.Command{
	Use:   "new",
	Short: "Generate new template",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("new called")
	},
}

func init() {
	rootCmd.AddCommand(newCmd)
	newCmd.PersistentFlags().StringVarP(&name, "name", "n", "", "Template name")
	newCmd.PersistentFlags().StringVar(&includeURLs, "include-urls", "", "Include URLs from the file")
	newCmd.PersistentFlags().StringVar(&includeRoles, "include-roles", "", "Include Roles from the file")
	newCmd.PersistentFlags().StringVar(&successStatus, "policy-success-status", "", "Set success status policy")
	newCmd.PersistentFlags().StringVar(&failStatus, "policy-fail-status", "", "Set fail status policy")
	newCmd.PersistentFlags().StringVar(&failRegex, "policy-fail-regex", "", "Set fail regex policy")
	newCmd.PersistentFlags().IntVar(&failSize, "policy-fail-size", 0, "Set fail size policy")
}
