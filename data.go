package api

import (
	"fmt"
	"strings"
)

func GetEntryFile(stream string, index int64) string {
	return fmt.Sprintf("%s-%d_entry.json", strings.Replace(stream, ".", "_", -1), index)
}
