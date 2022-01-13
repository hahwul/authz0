package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/hahwul/authz0/pkg/logger"
	"github.com/hahwul/authz0/pkg/report"
	"github.com/hahwul/authz0/pkg/scan"
	"github.com/spf13/cobra"
)

var cookie, scanRolename, proxyAddress, resultFormat string
var headers []string
var concurrency, delay, timeout int
var noReport bool

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan <filename>",
	Short: "Scanning",
	Run: func(cmd *cobra.Command, args []string) {

		log := logger.GetLogger(debug)
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
			log.Info("start scan 🚀")
			results := scan.Run(args[0], scanArguments, debug)
			log.Info("complete scan 🎉")

			if !noReport {
				log.Info("generate report 🔖")
				if resultFormat == "json" {
					e, _ := json.Marshal(&results)
					r, _ := report.PrettyJSON(e)
					fmt.Println(string(r))
				} else {
					report.PrintTableReport(results, resultFormat)
				}
			}
		} else {
			log.Fatal("please input template file")
		}
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.PersistentFlags().StringVarP(&cookie, "cookie", "c", "", "Cookie value of this test case")
	scanCmd.PersistentFlags().StringVarP(&scanRolename, "rolename", "r", "", "Role name of this test case")
	scanCmd.PersistentFlags().StringVar(&proxyAddress, "proxy", "", "Proxy address")
	scanCmd.PersistentFlags().StringVarP(&resultFormat, "format", "f", "", "Result format (plain, json, markdown)")
	scanCmd.PersistentFlags().StringSliceVarP(&headers, "header", "H", []string{}, "Headers of this test case")
	scanCmd.PersistentFlags().IntVar(&concurrency, "concurrency", 1, "Number of URLs to be test in parallel")
	scanCmd.PersistentFlags().IntVar(&delay, "delay", 0, "Second of Delay to HTTP Request")
	scanCmd.PersistentFlags().IntVar(&timeout, "timeout", 10, "Second of Timeout to HTTP Request")
	scanCmd.PersistentFlags().BoolVar(&noReport, "no-report", false, "Not print report (only log mode)")
}
