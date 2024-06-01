# Subgomain

Subgomain is a command-line tool for checking domains for vulnerabilities related to subdomain takeover. It checks a list of domains provided via input against known fingerprints stored in a JSON file. Possible vulnerabilities are identified through checks on DNS CNAME records, HTTP status codes, and string patterns in the HTML response content.

## Installation

You can install Subgomain using the following command:

```bash
go install -v github.com/topscoder/subgomain@latest
```

## Usage

```bash
subgomain -domains <filename> [-fingerprints <url_or_local_path>] [-threads <int>] [-timeout <seconds>] [-silent]
```

### Arguments

- `-domains <path-to-domains-file>`: Specifies the path to the file containing the list of domains to check. Required.
- `-fingerprints <url-to-fingerprints-json>` (optional): Specifies the URL or disk path to the JSON file containing fingerprints for identifying vulnerabilities. Optional. Defaults to a predefined URL.
- `-threads <number-of-threads>` (optional, default 5): Specifies the number of concurrent threads to use for domain checking. Optional. Defaults to the number of logical CPUs.
- `-timeout <seconds>` (optional, default 2): Specifies the HTTP timeout in seconds. Optional. Defaults to 2 seconds.
- `-silent` (optional): If provided, only prints vulnerable domains without any additional output. Optional.
- `-verbose` (optional): If provided, the application prints (loads of) debug messages.

## Examples

1. Check domains for vulnerabilities, printing both vulnerable and non-vulnerable domains:
   ```bash
   subgomain -domains domains.txt
   ```

2. Check domains for vulnerabilities, printing only vulnerable domains:
   ```bash
   subgomain -silent -domains domains.txt
   ```

3. Check domains using custom fingerprints file and increase the number of threads for faster processing:
   ```bash
   subgomain -domains domains.txt -fingerprints https://example.com/custom_fingerprints.json -threads 10
   ```

## Contributing

Contributions are welcome! If you have suggestions, feature requests, or find a bug, please open an issue or submit a pull request.

## License

This project is licensed under the MIT License.