# certificate-crl-ocsp-check

[![Super-Linter](https://github.com/rokris/certificate-crl-ocsp-check/actions/workflows/superlint.yml/badge.svg)](https://github.com/marketplace/actions/super-linter)

# SSL Certificate Revocation Checker

This Python script is designed to check the revocation status of SSL certificates for a list of servers. It performs checks using both Certificate Revocation Lists (CRLs) and Online Certificate Status Protocol (OCSP). The script also provides options for debugging and can be executed with different configurations based on your needs.

## Features

- **Retrieve SSL Certificates**: Fetches SSL certificates from specified servers.
- **CRL Check**: Downloads and parses Certificate Revocation Lists (CRLs) to determine if a certificate has been revoked.
- **OCSP Check**: Verifies the status of a certificate using the Online Certificate Status Protocol (OCSP).
- **Debugging**: Offers detailed output for troubleshooting purposes.
- **Color-coded Output**: Displays results with color-coded messages (red for errors, green for success).

## Installation

1. Clone the repository:

   ```sh
   git clone https://github.com/yourusername/ssl-cert-checker.git
   cd ssl-cert-checker
   ```

2. Install the required dependencies:

   ```sh
   pip install -r requirements.txt
   ```

## Usage

You can use this script by either specifying a list of servers via a file or by passing server addresses directly through the command line.

### Command-line Arguments

- `--serverliste`: (Optional) Path to a file containing a list of server addresses to process.
- `--crl-liste`: (Optional) Path to a file containing known serial numbers for comparison.
- `--debug`: (Optional) Enables detailed debugging information.
- `--help`: Displays the help message.

### Example Command

```sh
python check_revocation.py --serverliste servers.txt --crl-liste serials.txt --debug
```

This command checks the revocation status of servers listed in servers.txt against the serial numbers in serials.txt and prints detailed debugging information.

Example Server List Format
The server list file (servers.txt) should contain one server address per line:

```sh
example.com
https://anotherexample.com
https://anotherexample.com:8443
example.com:443
```

Example CRL List Format
The CRL list file (serials.txt) should contain one serial number per line, formatted as a 32-character hexadecimal string:

```sh
0123456789ABCDEF0123456789ABCDEF
FEDCBA9876543210FEDCBA9876543210
```

Dependencies
This script relies on the following Python libraries:

- requests
- cryptography
- colorama
- certifi
- ocspchecker

Install them with:

```sh
pip install -r requirements.txt
```

Contributing
Contributions are welcome!

Please fork this repository, make your changes, and submit a pull request.
