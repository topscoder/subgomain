package main

import (
	"flag"
	"fmt"
	"os"
	"sync"

	"github.com/topscoder/subgomain/domainchecker"
	"github.com/topscoder/subgomain/fingerprints"
	"github.com/topscoder/subgomain/utils"
)

func main() {
	// Define command-line flags
	domainsFile := flag.String("domains", "", "The file containing the domains to be checked")
	fingerprintsURL := flag.String("fingerprints", "https://raw.githubusercontent.com/topscoder/Subdominator/master/Subdominator/custom_fingerprints.json", "URL to the online fingerprints.json file to be used")
	threads := flag.Int("threads", 5, "The amount of threads to be used")

	// Parse command-line flags
	flag.Parse()

	// Check if the domains file is provided
	if *domainsFile == "" {
		fmt.Println("Usage: subgomain -domains <filename> [-fingerprints <url>] [-threads <int>]")
		os.Exit(1)
	}

	// Load fingerprints
	fps, err := fingerprints.LoadFingerprints(*fingerprintsURL)
	if err != nil {
		fmt.Printf("Error loading fingerprints: %v\n", err)
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

	// Create a wait group to manage goroutines
	var wg sync.WaitGroup

	// Create worker goroutines
	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range domainChan {
				vulnerable, err := domainchecker.CheckDomain(domain, fps)
				if err != nil {
					fmt.Printf("Error checking domain %s: %v\n", domain, err)
					continue
				}

				if vulnerable {
					fmt.Printf("Domain %s is vulnerable!\n", domain)
				} else {
					fmt.Printf("Domain %s is not vulnerable.\n", domain)
				}
			}
		}()
	}

	// Wait for all goroutines to finish
	wg.Wait()
}
