package cmd

import (
	"github.com/hahwul/authz0/pkg/models"
	set "github.com/hahwul/authz0/pkg/set"
	"github.com/spf13/cobra"
)

var url, method, contentType, body string
var allowRole, denyRole []string

// setUrlCmd represents the setUrl command
var setUrlCmd = &cobra.Command{
	Use:   "setUrl <filename>",
	Short: "Append URL to Template",
	Run: func(cmd *cobra.Command, args []string) {
		url := models.URL{
			URL:       url,
			Method:    method,
			AllowRole: allowRole,
			DenyRole:  denyRole,
		}
		if len(args) >= 1 {
			set.SetURL(args[0], url)
		}
	},
}

func init() {
	rootCmd.AddCommand(setUrlCmd)

	setUrlCmd.PersistentFlags().StringVarP(&url, "url", "u", "", "Request URL")
	setUrlCmd.PersistentFlags().StringVarP(&method, "method", "X", "GET", "Request Method")
	setUrlCmd.PersistentFlags().StringVarP(&body, "body", "d", "", "Request Body data")
	setUrlCmd.PersistentFlags().StringVarP(&contentType, "type", "t", "form", "Request Type [form, json]")
	setUrlCmd.PersistentFlags().StringSliceVar(&allowRole, "allowRole", []string{}, "Allow role names")
	setUrlCmd.PersistentFlags().StringSliceVar(&denyRole, "denyRole", []string{}, "Deny role names")
}
