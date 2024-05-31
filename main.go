package main

import (
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/topscoder/subgomain/domainchecker"
	"github.com/topscoder/subgomain/fingerprints"
	"github.com/topscoder/subgomain/utils"
)

func main() {
	// Define command-line flags
	domainsFile := flag.String("domains", "", "The file containing the domains to be checked")
	fingerprintsArg := flag.String("fingerprints", "", "URL or local file path to the fingerprints.json file to be used")
	threads := flag.Int("threads", 5, "The amount of threads to be used")
	silent := flag.Bool("silent", false, "Only print vulnerable domains")
	timeout := flag.Int("timeout", 2, "Timeout in seconds for HTTP requests")

	// Parse command-line flags
	flag.Parse()

	// Check if the domains file is provided
	if *domainsFile == "" {
		fmt.Println("Usage: subgomain -domains <filename> [-fingerprints <url_or_local_path>] [-threads <int>] [-timeout <seconds>] [-silent]")
		os.Exit(1)
	}

	// Load fingerprints
	var fps []fingerprints.Fingerprint
	var err error
	if *fingerprintsArg != "" {
		fps, err = loadFingerprints(*fingerprintsArg)
		if err != nil {
			fmt.Printf("Error loading fingerprints: %v\n", err)
			os.Exit(1)
		}
	}

	resolvers, err := utils.LoadResolvers("https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt")
	if err != nil {
		fmt.Printf("Error loading resolvers: %v\n", err)
		os.Exit(1)
	}

	// Read domains from file
	domains, err := utils.ReadDomainsFromFile(*domainsFile)
	if err != nil {
		fmt.Printf("Error reading domains: %v\n", err)
		os.Exit(1)
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
