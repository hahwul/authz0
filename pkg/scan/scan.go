package scan

type ScanArguments struct {
	RoleName string
	Cookie   string
	Headers  []string
}

func Run(filename string, arguments ScanArguments), {
	template := authz0.FileToTemplate(filename)
	_ = template
	// TODO: Add scanning logic
}
