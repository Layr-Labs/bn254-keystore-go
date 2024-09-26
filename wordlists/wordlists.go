package wordlists

import (
	"fmt"
	"path/filepath"
	"runtime"
)

func GetWordListFolderPath() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		fmt.Println("Unable to get current file path")
		return ""
	}

	return filepath.Dir(filename)
}
