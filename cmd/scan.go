package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strconv"

	"github.com/hahwul/authz0/pkg/logger"
	"github.com/hahwul/authz0/pkg/report"
	"github.com/hahwul/authz0/pkg/scan"
	"github.com/spf13/cobra"
)

var cookie, scanRolename, proxyAddress, resultFormat, resultFile string
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
			log.Info("complete scan")
			rcount := 0
			for _, r := range results {
				if r.Result == "X" {
					rcount = rcount + 1
				}
			}
			if rcount > 0 {
				log.Info("found " + strconv.Itoa(rcount) + " issues")
			} else {
				log.Info("not found issues")
			}
			if !noReport {
				log.Info("generating report..")
				rlog := log.WithField("type", "reporter")
				if resultFormat == "json" {
					e, _ := json.Marshal(&results)
					r, _ := report.PrettyJSON(e)
					fmt.Println(string(r))
					if resultFile != "" {
						err := ioutil.WriteFile(resultFile, r, 0644)
						if err != nil {
							rlog.Error("file write error")
						} else {
							rlog.Info("output file write success")
						}
					}
				} else {
					rlog.Info("assert & role reports")
					report.PrintTableReport(results, resultFormat)
					rlog.Info("url indexes")
					report.PrintTableURLs(results, resultFormat)
				}
			}
		} else {
			log.Fatal("please input template file")
		}
		log.Info("finish 🎉")
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.PersistentFlags().StringVarP(&cookie, "cookie", "c", "", "Cookie value of this test case")
	scanCmd.PersistentFlags().StringVarP(&scanRolename, "rolename", "r", "", "Role name of this test case")
	scanCmd.PersistentFlags().StringVar(&proxyAddress, "proxy", "", "Proxy address")
	scanCmd.PersistentFlags().StringVarP(&resultFormat, "format", "f", "", "Result format (plain, json, markdown)")
	scanCmd.PersistentFlags().StringVarP(&resultFile, "output", "o", "", "Save result to output file")
	scanCmd.PersistentFlags().StringSliceVarP(&headers, "header", "H", []string{}, "Headers of this test case (support duplicate flag)")
	scanCmd.PersistentFlags().IntVar(&concurrency, "concurrency", 1, "Number of URLs to be test in parallel")
	scanCmd.PersistentFlags().IntVar(&delay, "delay", 0, "Second of Delay to HTTP Request")
	scanCmd.PersistentFlags().IntVar(&timeout, "timeout", 10, "Second of Timeout to HTTP Request")
	scanCmd.PersistentFlags().BoolVar(&noReport, "no-report", false, "Not print report (only log mode)")
}
