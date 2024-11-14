package wordlists

import (
	"embed"
	"fmt"
	"strings"
)

//go:embed all:files/*
var staticFiles embed.FS

func GetWordList(language string) ([]string, error) {
	data, err := staticFiles.ReadFile("files/" + fmt.Sprintf("%s.txt", language))
	if err != nil {
		return nil, err
	}
	content := string(data)
	wordList := strings.Split(content, "\n")
	return wordList, nil
}
