package domainchecker

import (
	"context"
	"crypto/tls"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/topscoder/subgomain/fingerprints"
	"github.com/topscoder/subgomain/logger"
)

// ResolverIndex keeps track of the current resolver index
var ResolverIndex int

// initializeResolverIndex initializes ResolverIndex with a random value
func initializeResolverIndex(resolvers []string) {
	rand.Seed(time.Now().UnixNano())
	ResolverIndex = rand.Intn(len(resolvers))
}

// rotateResolver rotates to the next resolver
func rotateResolver(resolvers []string) string {
	resolver := resolvers[ResolverIndex]
	ResolverIndex = (ResolverIndex + 1) % len(resolvers)
	return resolver
}

// CheckDomain checks if the given domain is vulnerable based on the fingerprints.
func CheckDomain(domain string, fingerprints []fingerprints.Fingerprint, resolvers []string, httpTimeout time.Duration) (string, *fingerprints.Fingerprint, error) {

	// Initialize ResolverIndex with a random value on the first call
	if ResolverIndex == 0 {
		initializeResolverIndex(resolvers)
	}

	// Create a context with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()

	// Rotate resolver
	resolverAddress := rotateResolver(resolvers) + ":53"

	// Create a resolver with the context
	resolver := net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", resolverAddress)
		},
	}

	logger.LogDebug("[%s] Checking domain", domain)
	logger.LogDebug("[%s] Using resolver: %s", domain, resolverAddress)

	// Fetch CNAME
	cname, cnameErr := resolver.LookupCNAME(ctx, domain)
	if cnameErr != nil {
		logger.LogDebug("[%s] Error fetching CNAME: %s", domain, cnameErr)
	} else {
		logger.LogDebug("[%s] Fetched CNAME: %s", domain, cname)
	}

	// Fetch IP's (A/AAAA records)
	ips, aRecordErr := resolver.LookupIP(ctx, "ip", domain)
	if aRecordErr != nil {
		logger.LogDebug("[%s] Error fetching IP's: %s", domain, aRecordErr)
	} else {
		logger.LogDebug("[%s] Fetched IP's: %s", domain, ips)
	}

	// Create a custom HTTP transport that skips SSL/TLS certificate verification
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Transport: tr,
		Timeout:   httpTimeout,
	}

	// Make HTTPS GET request with timeout
	responseBody := ""
	req, httpsGetErr := http.NewRequest("GET", "https://"+domain, nil)
	if httpsGetErr == nil {
		resp, doHttpsGetErr := client.Do(req)
		if doHttpsGetErr == nil {
			body, readBodyErr := ioutil.ReadAll(resp.Body)
			if readBodyErr == nil {
				responseBody = string(body)
			}
		}
	}

	for _, fp := range fingerprints {

		// Skip fingerprints that are not vulnerable to takeover
		// to speedup the scanning process a bit
		if !fp.Vulnerable {
			logger.LogDebug("Skip fingerprint for %s (NOT VULNERABLE)", fp.Service)
			continue
		}

		// Loop through all of the fingerprints
		// And match the indicators.
		// If all required indicators are matched,
		// we have a possible subdomain takeover vulnerability.
		logger.LogDebug("[%s] Matching fingerprint for service: %s", domain, fp.Service)

		matchedCname := ""
		matchFingerprint := ""
		matchedARecord := ""

		if len(fp.CNAME) > 0 {
			// This fingerprint requires a matching CNAME indicator
			if cnameErr == nil {
				for _, cnameEntry := range fp.CNAME {
					logger.LogDebug("[%s] - Finding CNAME record: %s", domain, cnameEntry)
					if cnameEntry != "" && strings.Contains(cname, cnameEntry) {
						logger.LogDebug("[%s] [MATCH] - Matched CNAME record: %s", domain, cnameEntry)
						matchedCname = cname
						break
					}
				}
			}

			if matchedCname == "" {
				continue
			}
		}

		if len(fp.A) > 0 {
			// This fingerprint requires a matching A record indicator
			if aRecordErr == nil {
				for _, aRecord := range fp.A {
					if aRecord != "" {
						logger.LogDebug("[%s] - Finding A record: %s", domain, aRecord)
						for _, ip := range ips {
							if aRecord != "" && strings.Contains(ip.String(), aRecord) {
								logger.LogDebug("[%s] [MATCH] - Matched A record: %s", domain, aRecord)
								matchedARecord = ip.String()
								break
							}
						}
					}
				}
			}

			if matchedARecord == "" {
				continue
			}
		}

		if len(fp.Fingerprint) > 0 {
			// This fingerprint requires a string match fingerprint indicator
			for _, fingerprint := range fp.Fingerprint {
				logger.LogDebug("[%s] - Finding fingerprint string: %s", domain, fingerprint)
				if fingerprint != "" && strings.Contains(string(responseBody), fingerprint) {
					logger.LogDebug("[%s] [MATCH] - Matched fingerprint string: %s", domain, fingerprint)
					matchFingerprint = fingerprint
					break
				}
			}

			if matchFingerprint == "" {
				continue
			}
		}

		if matchedCname != "" || matchedARecord != "" || matchFingerprint != "" {
			return "CNAME: " + matchedCname + " | A: " + matchedARecord + " | Fingerprint: " + matchFingerprint, &fp, nil
		}
	}

	return "", nil, nil
}
