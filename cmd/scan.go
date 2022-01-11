package cmd

import (
	"github.com/hahwul/authz0/pkg/scan"
	"github.com/spf13/cobra"
)

var cookie, scanRolename string
var headers []string

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan <filename>",
	Short: "Scanning",
	Run: func(cmd *cobra.Command, args []string) {
		scanArguments := scan.ScanArguments{
			RoleName: scanRolename,
			Cookie:   cookie,
			Headers:  headers,
		}
		if len(args) >= 1 {
			scan.Run(args[0], scanArguments)
		}
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.PersistentFlags().StringVarP(&cookie, "cookie", "c", "", "Cookie value of this test case")
	scanCmd.PersistentFlags().StringVarP(&scanRolename, "rolename", "r", "", "Role name of this test case")
	scanCmd.PersistentFlags().StringSliceVarP(&headers, "header", "H", []string{}, "Headers of this test case")
}
