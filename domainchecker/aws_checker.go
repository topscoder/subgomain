// domainchecker/aws_checker.go
package domainchecker

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	"github.com/topscoder/subgomain/logger"
)

func parseFQDN(fqdn string) (string, string, string, error) {
	parts := strings.Split(fqdn, ".")
	if len(parts) < 3 {
		return "", "", "", fmt.Errorf("invalid FQDN format")
	}

	region := parts[len(parts)-3]
	if len(parts) == 4 {
		appName := parts[0]
		return appName, "", region, nil
	} else if len(parts) == 5 {
		appName := parts[0]
		id := parts[1]
		return appName, id, region, nil
	}
	return "", "", "", fmt.Errorf("invalid FQDN format")
}

func CheckDNSAvailability(fqdn string) (bool, error) {
	logger.LogDebug("[%s] Service validation: AWS Elastic Beanstalk", fqdn)

	appName, id, region, err := parseFQDN(fqdn)
	if err != nil {
		return false, err
	}

	var cnamePrefix string
	if id != "" {
		cnamePrefix = id
	} else {
		cnamePrefix = appName
	}

	// Member Don't start domain name with 'eba-'
	if strings.HasPrefix(id, "eba-") || strings.HasPrefix(appName, "eba-") {
		logger.LogDebug("[%s] Domain name cannot start with 'eba-' on AWS Elastic Beanstalk.\n", fqdn)
		return false, nil
	}

	// Load the AWS configuration
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		return false, err
	}

	// Create an Elastic Beanstalk client
	svc := elasticbeanstalk.NewFromConfig(cfg)

	// Create the input for the CheckDNSAvailability API call
	input := &elasticbeanstalk.CheckDNSAvailabilityInput{
		CNAMEPrefix: aws.String(cnamePrefix),
	}

	// Call CheckDNSAvailability
	result, err := svc.CheckDNSAvailability(context.TODO(), input)
	if err != nil {
		return false, err
	}

	if result.Available != nil && *result.Available {
		logger.LogDebug("[%s] The domain is available on AWS Elastic Beanstalk.\n", fqdn)
	} else {
		logger.LogDebug("[%s] The domain is not available on AWS Elastic Beanstalk.\n", fqdn)
	}

	// Return the availability result
	return result.Available != nil && *result.Available, nil
}
