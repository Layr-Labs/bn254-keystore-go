package wordlists

import (
	"embed"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
)

//go:embed all:files/*
var staticFiles embed.FS

func GetWordListFolderPath() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		fmt.Println("Unable to get current file path")
		return ""
	}

	return filepath.Dir(filename)
}

func GetWordList(language string) ([]string, error) {
	data, err := staticFiles.ReadFile("files/" + fmt.Sprintf("%s.txt", language))
	if err != nil {
		return nil, err
	}
	content := string(data)
	wl := strings.Split(content, "\n")
	return wl, nil
}
