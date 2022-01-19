package cmd

import (
	"github.com/hahwul/authz0/pkg/authz0"
	"github.com/hahwul/authz0/pkg/logger"
	new "github.com/hahwul/authz0/pkg/new"
	"github.com/spf13/cobra"
)

var name string
var includeURLs, includeRoles, includeHar, includeBurp string
var successStatus string
var failRegex string
var failStatus, failSize []int
var failSizeMargin int

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
			IncludeHAR:          includeHar,
			IncludeBurp:         includeBurp,
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
	newCmd.PersistentFlags().StringVar(&includeHar, "include-zap", "", "Include ZAP log file (HAR)")
	newCmd.PersistentFlags().StringVar(&includeHar, "include-har", "", "Include HAR file")
	newCmd.PersistentFlags().StringVar(&includeBurp, "include-burp", "", "Include Burp log file (XML)")
	newCmd.PersistentFlags().StringVar(&successStatus, "assert-success-status", "", "Set success status assert")
	newCmd.PersistentFlags().IntSliceVar(&failStatus, "assert-fail-status", []int{}, "Set fail status assert (support duplicate flag)")
	newCmd.PersistentFlags().StringVar(&failRegex, "assert-fail-regex", "", "Set fail regex assert")
	newCmd.PersistentFlags().IntSliceVar(&failSize, "assert-fail-size", []int{}, "Set fail size assert (support duplicate flag)")
	newCmd.PersistentFlags().IntVar(&failSizeMargin, "assert-fail-size-margin", 0, "Set approximation range of fail size assert")
}
