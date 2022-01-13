package cmd

import (
	"github.com/hahwul/authz0/pkg/logger"
	"github.com/hahwul/authz0/pkg/models"
	set "github.com/hahwul/authz0/pkg/set"
	"github.com/spf13/cobra"
)

var rolename string

// setRoleCmd represents the setRole command
var setRoleCmd = &cobra.Command{
	Use:   "setRole <filename>",
	Short: "Append Role to Template",
	Run: func(cmd *cobra.Command, args []string) {

		log := logger.GetLogger(debug)
		role := models.Role{
			Name: rolename,
		}
		if len(args) >= 1 {
			set.SetRole(args[0], role)
			log.Info("added Role")
		} else {
			log.Fatal("please input template file")
		}

	},
}

func init() {
	rootCmd.AddCommand(setRoleCmd)
	setRoleCmd.PersistentFlags().StringVarP(&rolename, "name", "n", "", "Role name")
}
