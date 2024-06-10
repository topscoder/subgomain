package main

import (
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/topscoder/subgomain/domainchecker"
	"github.com/topscoder/subgomain/fingerprints"
	"github.com/topscoder/subgomain/logger"
	"github.com/topscoder/subgomain/utils"
)

func main() {
	// Define command-line flags
	domain := flag.String("domain", "", "A single domain to be checked")
	domainsFile := flag.String("domains", "", "The file containing the domains to be checked")
	fingerprintsArg := flag.String("fingerprints", "", "URL or local file path to the fingerprints.json file to be used")
	resolversArg := flag.String("resolvers", "", "URL to the resolvers.txt file to be used")
	threads := flag.Int("threads", 5, "The amount of threads to be used")
	timeout := flag.Int("timeout", 2, "Timeout in seconds for HTTP requests")
	silent := flag.Bool("silent", false, "Only print vulnerable domains")
	debug := flag.Bool("debug", false, "enable debug logging")

	flag.Parse()

	logger.SetVerbose(debug)

	// Check if the domains file is provided
	if *domain == "" && *domainsFile == "" {
		fmt.Println("Usage: subgomain -domain <domain> | -domains <filename> [-fingerprints <url_or_local_path>] [-threads <int>] [-timeout <seconds>] [-silent]")
		os.Exit(1)
	}

	// Load fingerprints
	var fps []fingerprints.Fingerprint
	var err error
	fingerprintFile := ""
	if *fingerprintsArg != "" {
		fingerprintFile = *fingerprintsArg
	} else {
		fingerprintFile = "https://raw.githubusercontent.com/topscoder/subgomain/main/tests/testfingerprints.json"
	}

	fps, err = loadFingerprints(fingerprintFile)
	if err != nil {
		fmt.Printf("Error loading fingerprints: %v\n", err)
		os.Exit(1)
	}

	// Load resolvers
	resolversFile := ""
	if *resolversArg != "" {
		resolversFile = *resolversArg
	} else {
		resolversFile = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
	}

	logger.LogDebug("Downloading resolvers list from ", resolversFile)

	resolvers, err := utils.LoadResolvers(resolversFile)
	if err != nil {
		fmt.Printf("Error loading resolvers: %v\n", err)
		os.Exit(1)
	}

	var domains []string

	// If a single domain is provided, use it
	if *domain != "" {
		domains = []string{*domain}
	} else {
		// Read domains from file
		domains, err = utils.ReadDomainsFromFile(*domainsFile)
		if err != nil {
			fmt.Printf("Error reading domains: %v\n", err)
			os.Exit(1)
		}
	}

	// Create a channel to manage domain processing
	domainChan := make(chan string, len(domains))
	for _, domain := range domains {
		domainChan <- domain
	}
	close(domainChan)

	httpTimeout := time.Duration(*timeout) * time.Second

	// Create a wait group to manage goroutines
	var wg sync.WaitGroup

	// Create worker goroutines
	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range domainChan {
				vulnerable, fingerprint, err := domainchecker.CheckDomain(domain, fps, resolvers, httpTimeout)
				if err != nil {
					if !*silent {
						fmt.Printf("[ERROR] %s: %v\n", domain, err)
					}
					continue
				}

				if vulnerable && (fingerprint.Vulnerable || fingerprint.Status == "Vulnerable") {
					fmt.Printf("[VULNERABLE] [%s] %s \n", fingerprint.Service, domain)
				} else {
					if !*silent {
						fmt.Printf("[NOT VULNERABLE] %s\n", domain)
					}
				}
			}
		}()
	}

	// Wait for all goroutines to finish
	wg.Wait()
}

func loadFingerprints(fingerprintsArg string) ([]fingerprints.Fingerprint, error) {
	if utils.IsValidURL(fingerprintsArg) {
		// Load fingerprints from URL
		return fingerprints.LoadFingerprints(fingerprintsArg)
	}

	// Load fingerprints from local file
	return fingerprints.LoadFingerprintsFromFile(fingerprintsArg)
}
