package utils

import "strings"

func ContainsFromArray(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	t := strings.Split(item, "(")
	i := t[0]
	for _, s := range slice {
		set[s] = struct{}{}
	}

	_, ok := set[i]
	return ok
}
