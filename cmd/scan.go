package cmd

import (
	"github.com/hahwul/authz0/pkg/scan"
	"github.com/spf13/cobra"
)

var cookie, scanRolename, proxyAddress string
var headers []string
var concurrency, delay, timeout int

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan <filename>",
	Short: "Scanning",
	Run: func(cmd *cobra.Command, args []string) {
		scanArguments := scan.ScanArguments{
			RoleName:     scanRolename,
			Cookie:       cookie,
			Headers:      headers,
			Concurrency:  concurrency,
			Delay:        delay,
			ProxyAddress: proxyAddress,
			Timeout:      timeout,
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
	scanCmd.PersistentFlags().StringVar(&proxyAddress, "proxy", "", "Proxy address")
	scanCmd.PersistentFlags().StringSliceVarP(&headers, "header", "H", []string{}, "Headers of this test case")
	scanCmd.PersistentFlags().IntVar(&concurrency, "concurrency", 10, "Number of URLs to be test in parallel")
	scanCmd.PersistentFlags().IntVar(&delay, "delay", 0, "Second of Delay to HTTP Request")
	scanCmd.PersistentFlags().IntVar(&timeout, "timeout", 10, "Second of Timeout to HTTP Request")
}
