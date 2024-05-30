package utils

import (
	"bufio"
	"net/http"
	"net/url"
	"os"
	"strings"
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

// IsValidURL checks if the given string is a valid URL.
func IsValidURL(s string) bool {
	_, err := url.ParseRequestURI(s)
	if err != nil {
		return false
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	return true
}

// LoadResolvers loads DNS resolvers from a URL
func LoadResolvers(url string) ([]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var resolvers []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		resolver := strings.TrimSpace(scanner.Text())
		if resolver != "" {
			resolvers = append(resolvers, resolver)
		}
	}
	return resolvers, scanner.Err()
}
