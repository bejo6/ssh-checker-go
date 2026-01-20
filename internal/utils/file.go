package utils

import (
	"os"
	"strings"
)

func GetItemsFromFile(filePath string) ([]string, error) {
	file, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var items []string
	lines := strings.Split(string(file), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			items = append(items, line)
		}
	}

	return items, nil
}
