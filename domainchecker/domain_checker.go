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
func CheckDomain(domain string, fingerprints []fingerprints.Fingerprint, resolvers []string, httpTimeout time.Duration) (bool, *fingerprints.Fingerprint, error) {

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

	cname, cnameErr := resolver.LookupCNAME(ctx, domain)

	logger.LogDebug("[%s] Fetched CNAME: %s", domain, cname)

	ips, aRecordErr := resolver.LookupIP(ctx, "ip", domain)

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
		// Loop through all of the fingerprints
		// And match the indicators.
		// If all required indicators are matched,
		// we have a possible subdomain takeover vulnerability.
		logger.LogDebug("[%s] Matching fingerprint for service: %s", domain, fp.Service)

		matchedCname := false
		matchFingerprint := false
		matchedARecord := false

		if cnameErr == nil && len(fp.CNAME) > 0 {
			// This fingerprint requires a matching CNAME indicator
			for _, cnameEntry := range fp.CNAME {
				logger.LogDebug("[%s] - Finding CNAME record: %s", domain, cnameEntry)
				if cnameEntry != "" && strings.Contains(cname, cnameEntry) {
					matchedCname = true
					break
				}
			}

			if !matchedCname {
				continue
			}
		}

		if aRecordErr == nil && len(fp.A) > 0 {
			// This fingerprint requires a matching A record indicator
			for _, aRecord := range fp.A {
				if aRecord != "" {
					logger.LogDebug("[%s] - Finding A record: %s", domain, aRecord)
					for _, ip := range ips {
						if aRecord == ip.String() {
							matchedARecord = true
							break
						}
					}
				}
			}

			if !matchedARecord {
				continue
			}
		}

		if len(fp.Fingerprint) > 0 {
			// This fingerprint requires a string match fingerprint indicator
			for _, fingerprint := range fp.Fingerprint {
				if fingerprint != "" && strings.Contains(string(responseBody), fingerprint) {
					logger.LogDebug("[%s] - Finding fingerprint string: %s", domain, fingerprint)
					matchFingerprint = true
					break
				}
			}

			if !matchFingerprint {
				continue
			}
		}

		if matchedCname || matchedARecord || matchFingerprint {
			return true, &fp, nil
		}
	}

	return false, nil, nil
}
