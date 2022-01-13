package cmd

import (
	"github.com/hahwul/authz0/pkg/authz0"
	"github.com/hahwul/authz0/pkg/logger"
	new "github.com/hahwul/authz0/pkg/new"
	"github.com/spf13/cobra"
)

var name string
var includeURLs, includeRoles string
var successStatus string
var failStatus, failRegex string
var failSize int

// newCmd represents the new command
var newCmd = &cobra.Command{
	Use:   "new <filename>",
	Short: "Generate new template",
	Run: func(cmd *cobra.Command, args []string) {
		var filename string
		log := logger.GetLogger(debug)
		if len(args) >= 1 {
			filename = args[0]
		} else {
			filename = authz0.DefaultFile
		}
		newOptions := new.NewArguments{
			Filename:            filename,
			Name:                name,
			IncludeURLs:         includeURLs,
			IncludeRoles:        includeRoles,
			AssertSuccessStatus: successStatus,
			AssertFailStatus:    failStatus,
			AssertFailRegex:     failRegex,
			AssertFailSize:      failSize,
		}
		new.Generate(newOptions)
		log.WithField("filename", filename).Info("generate template")
	},
}

func init() {
	rootCmd.AddCommand(newCmd)
	newCmd.PersistentFlags().StringVarP(&name, "name", "n", "", "Template name")
	newCmd.PersistentFlags().StringVar(&includeURLs, "include-urls", "", "Include URLs from the file")
	newCmd.PersistentFlags().StringVar(&includeRoles, "include-roles", "", "Include Roles from the file")
	newCmd.PersistentFlags().StringVar(&successStatus, "assert-success-status", "", "Set success status assert")
	newCmd.PersistentFlags().StringVar(&failStatus, "assert-fail-status", "", "Set fail status assert")
	newCmd.PersistentFlags().StringVar(&failRegex, "assert-fail-regex", "", "Set fail regex assert")
	newCmd.PersistentFlags().IntVar(&failSize, "assert-fail-size", -1, "Set fail size assert")
}
