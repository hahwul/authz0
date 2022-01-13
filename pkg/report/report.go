package report

import (
	"bytes"
	"encoding/json"
	"os"
	"strconv"
	"strings"

	"github.com/hahwul/authz0/pkg/models"
	"github.com/olekukonko/tablewriter"
)

func PrettyJSON(b []byte) ([]byte, error) {
	var out bytes.Buffer
	err := json.Indent(&out, b, "", "  ")
	return out.Bytes(), err
}

func PrintTableReport(data []models.Result, t string) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Alias", "Method", "URL", "Code", "Assert", "Role", "Allow-Role", "Deny-Role", "Allow", "Deny", "Result"})
	if t == "markdown" {
		table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
		table.SetCenterSeparator("|")
	}
	table.SetHeaderColor(
		nil, nil, nil, nil,
		tablewriter.Colors{tablewriter.BgCyanColor, tablewriter.FgWhiteColor},
		nil,
		tablewriter.Colors{tablewriter.BgCyanColor, tablewriter.FgWhiteColor},
		tablewriter.Colors{tablewriter.BgRedColor, tablewriter.FgWhiteColor},
		tablewriter.Colors{tablewriter.BgCyanColor, tablewriter.FgWhiteColor},
		tablewriter.Colors{tablewriter.BgRedColor, tablewriter.FgWhiteColor},
		tablewriter.Colors{tablewriter.FgHiRedColor, tablewriter.Bold, tablewriter.BgBlackColor},
	)

	issue := 0
	for _, v := range data {
		line := []string{
			v.Alias,
			v.Method,
			v.URL,
			strconv.Itoa(v.StatusCode),
			strconv.FormatBool(v.Assert),
			v.RoleName,
			strings.Join(v.AllowRole, ","),
			strings.Join(v.DenyRole, ","),
			strconv.FormatBool(v.AssertAllowRole),
			strconv.FormatBool(v.AssertDenyRole),
			v.Result,
		}
		if v.Result == "X" {
			issue = issue + 1
			table.Rich(line, []tablewriter.Colors{
				tablewriter.Colors{},
				tablewriter.Colors{},
				tablewriter.Colors{},
				tablewriter.Colors{},
				tablewriter.Colors{},
				tablewriter.Colors{},
				tablewriter.Colors{},
				tablewriter.Colors{},
				tablewriter.Colors{},
				tablewriter.Colors{},
				tablewriter.Colors{tablewriter.FgHiRedColor, tablewriter.Bold, tablewriter.BgBlackColor},
			})
		}
		table.Append(line)
	}
	table.SetCaption(true, "Found "+strconv.Itoa(issue)+" Issue")
	table.Render()
}
