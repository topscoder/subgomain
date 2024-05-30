package utils

import (
	"bufio"
	"os"
)

// ReadDomainsFromFile reads domains from the specified file.
func ReadDomainsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domains = append(domains, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return domains, nil
}
