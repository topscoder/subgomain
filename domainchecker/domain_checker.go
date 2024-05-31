package domainchecker

import (
	"context"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/topscoder/subgomain/fingerprints"
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

	// Check DNS with timeout
	cname, err := resolver.LookupCNAME(ctx, domain)
	if err != nil {
		return false, nil, err
	}

	if cname != "" {
		for _, fp := range fingerprints {
			for _, cnameEntry := range fp.CNAME {
				if strings.Contains(cname, cnameEntry) {
					return true, &fp, nil
				}
			}
		}
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: httpTimeout,
	}

	// Make HTTPS GET request with timeout
	req, err := http.NewRequest("GET", "https://"+domain, nil)
	if err != nil {
		return false, nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, nil, err
	}

	for _, fp := range fingerprints {
		if fp.HTTPStatus != nil && resp.StatusCode == *fp.HTTPStatus {
			for _, fingerprint := range fp.Fingerprint {
				if strings.Contains(string(body), fingerprint) {
					return true, &fp, nil
				}
			}
		}
	}

	return false, nil, nil
}
