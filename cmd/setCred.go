/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"github.com/hahwul/authz0/pkg/logger"
	"github.com/hahwul/authz0/pkg/models"
	set "github.com/hahwul/authz0/pkg/set"
	"github.com/spf13/cobra"
)

var credRolename string
var credHeaders []string

// setCredCmd represents the setCred command
var setCredCmd = &cobra.Command{
	Use:   "setCred",
	Short: "Append Credential to Template",
	Run: func(cmd *cobra.Command, args []string) {
		log := logger.GetLogger(debug)
		cred := models.Credential{
			Rolename: credRolename,
			Headers:  credHeaders,
		}
		if len(args) >= 1 {
			set.SetCred(args[0], cred)
			log.Info("added Credential")
		} else {
			log.Fatal("please input template file")
		}
	},
}

func init() {
	rootCmd.AddCommand(setCredCmd)
	setCredCmd.PersistentFlags().StringVarP(&credRolename, "name", "n", "", "Role name")
	setCredCmd.PersistentFlags().StringSliceVarP(&credHeaders, "headers", "H", []string{}, "Headers")
}
