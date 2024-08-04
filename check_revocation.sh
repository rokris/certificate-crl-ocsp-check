#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo
    echo "No hostname given to obtain certificate status"
    echo "\tuse: $0 www.example.com"
    echo
    exit 1
fi

echo
echo Getting certificate for $1 from TLS handshake

openssl s_client -connect $1:443 -servername $1 < /dev/null 2>&1 |  sed -n '/-----BEGIN/,/-----END/p' > certificate.pem

echo
echo Getting intermediates from TLS handshake

openssl s_client -showcerts -connect $1:443 < /dev/null 2>&1 |  sed -n '/-----BEGIN/,/-----END/p' | sed -n '/^-----END CERTIFICATE-----/,$ p' | sed 1d > chain.pem

echo
echo Finding OCSP server in certificate

ocsp=`openssl x509 -noout -ocsp_uri -in certificate.pem`

echo
echo Extracting hostname from OCSP url

## Remove protocol part of url  ##
host=$ocsp
host="${host#http://}"
host="${host#https://}"

## Remove rest of urls ##
host=${host%%/*}

echo
echo "Making OCSP request to $ocsp ($host) saving a copy of the request to ocsp.req and the response to ocsp.resp"

echo
openssl ocsp -noverify -no_nonce -respout ocsp.resp -reqout ocsp.req -issuer chain.pem -cert certificate.pem -text -url $ocsp -header 'Host' $host

echo
echo Making the same OCSP request via CURL
curl -v -o /dev/null --data-binary @ocsp.req -H "Content-Type: application/ocsp-request" --url $ocsp
