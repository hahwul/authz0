package cmd

import (
	"github.com/hahwul/authz0/pkg/logger"
	"github.com/hahwul/authz0/pkg/models"
	set "github.com/hahwul/authz0/pkg/set"
	"github.com/spf13/cobra"
)

var url, method, contentType, body, alias string
var allowRole, denyRole []string

// setUrlCmd represents the setUrl command
var setUrlCmd = &cobra.Command{
	Use:   "setUrl <filename>",
	Short: "Append URL to Template",
	Run: func(cmd *cobra.Command, args []string) {

		log := logger.GetLogger(debug)
		url := models.URL{
			URL:       url,
			Method:    method,
			AllowRole: allowRole,
			DenyRole:  denyRole,
			Alias:     alias,
		}
		if len(args) >= 1 {
			set.SetURL(args[0], url)
			log.Info("added URL")
		} else {
			log.Fatal("please input template file")
		}
	},
}

func init() {
	rootCmd.AddCommand(setUrlCmd)

	setUrlCmd.PersistentFlags().StringVarP(&url, "url", "u", "", "Request URL")
	setUrlCmd.PersistentFlags().StringVarP(&method, "method", "X", "GET", "Request Method")
	setUrlCmd.PersistentFlags().StringVarP(&body, "body", "d", "", "Request Body data")
	setUrlCmd.PersistentFlags().StringVarP(&contentType, "type", "t", "form", "Request Type [form, json]")
	setUrlCmd.PersistentFlags().StringVarP(&alias, "alias", "a", "", "Alias")
	setUrlCmd.PersistentFlags().StringSliceVar(&allowRole, "allowRole", []string{}, "Allow role names (support duplicate flag)")
	setUrlCmd.PersistentFlags().StringSliceVar(&denyRole, "denyRole", []string{}, "Deny role names (support duplicate flag)")
}
