package main

import (
	"fmt"
	"os"

	"github.com/topscoder/subgomain/domainchecker"
	"github.com/topscoder/subgomain/fingerprints"
	"github.com/topscoder/subgomain/utils"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: subgomain <path-to-domains-file>")
		os.Exit(1)
	}

	domainsFilePath := os.Args[1]

	fingerprints, err := fingerprints.LoadFingerprints("https://raw.githubusercontent.com/topscoder/Subdominator/master/Subdominator/custom_fingerprints.json")
	if err != nil {
		fmt.Printf("Error loading fingerprints: %v\n", err)
		os.Exit(1)
	}

	domains, err := utils.ReadDomainsFromFile(domainsFilePath)
	if err != nil {
		fmt.Printf("Error reading domains: %v\n", err)
		os.Exit(1)
	}

	for _, domain := range domains {
		vulnerable, err := domainchecker.CheckDomain(domain, fingerprints)
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
}
