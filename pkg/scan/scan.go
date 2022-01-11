package scan

import "github.com/hahwul/authz0/pkg/authz0"

type ScanArguments struct {
	RoleName string
	Cookie   string
	Headers  []string
}

func Run(filename string, arguments ScanArguments) {
	template := authz0.FileToTemplate(filename)
	// TODO: Add scanning logic
	for _, endpoint := range template.URLs {
		_ = endpoint
	}
}
