#!/bin/bash

# Funksjon for å hente sertifikatet fra en gitt URL, FTP eller SMTP
get_certificate() {
    local domain=$1
    local port=$2
    local starttls=$3

    case "$starttls" in
        ftp)
            openssl s_client -connect "$domain:$port" -starttls ftp </dev/null 2>/dev/null | openssl x509
            ;;
        smtp)
            openssl s_client -connect "$domain:$port" -starttls smtp </dev/null 2>/dev/null | openssl x509
            ;;
        *)
            openssl s_client -connect "$domain:$port" -servername "$domain" </dev/null 2>/dev/null | openssl x509
            ;;
    esac
}

# Funksjon for å sjekke om sertifikatet er tilbakekalt via OCSP
check_revocation_status() {
    local domain=$1
    local port=$2
    local starttls=$3

    # Hent sertifikat
    cert=$(get_certificate "$domain" "$port" "$starttls")

    if [ -z "$cert" ]; then
        echo "Kunne ikke hente sertifikatet for $domain."
        return 1
    fi

    # Ekstraher serienummeret
    serial_number=$(echo "$cert" | openssl x509 -noout -serial | sed 's/^serial=//')

    # Konverter serienummeret til heksadesimal format
    serial_number_hex=$(echo "$serial_number" | xxd -r -p | od -An -tx1 | tr -d ' \n')

    # Skriv ut serienummeret
    echo "Sertifikatets serienummer (desimal): $serial_number"
    echo "Sertifikatets serienummer (heksadesimal): $serial_number_hex"

    # Prøv å finne OCSP URL fra sertifikatet
    ocsp_url=$(echo "$cert" | openssl x509 -noout -ocsp_uri)

    if [ -z "$ocsp_url" ]; then
        echo "Kunne ikke finne OCSP URL i sertifikatet."
        return 1
    fi

    # Prøv å hente utstederens sertifikat URL fra "Authority Information Access" (AIA)
    issuer_url=$(echo "$cert" | openssl x509 -text -noout | grep -A1 "CA Issuers" | grep -o 'http[^ ]*')

    if [ -z "$issuer_url" ]; then
        echo "Kunne ikke finne utstederens sertifikat URL."
        return 1
    fi

    # Last ned utstederens sertifikat
    wget -q -O _issuer.pem "$issuer_url"
    if [ ! -s _issuer.pem ]; then
        echo "Kunne ikke laste ned eller fant ikke et gyldig utstedersertifikat."
        return 1
    fi

    # Sjekk sertifikatet mot OCSP
    echo "$cert" > _cert.pem
    response=$(openssl ocsp -issuer _issuer.pem -cert _cert.pem -url "$ocsp_url" -CAfile _issuer.pem -text 2>&1)

    if echo "$response" | grep -q "Cert Status: revoked"; then
        echo "Sertifikatet for $domain er tilbakekalt!"
    elif echo "$response" | grep -q "Cert Status: good"; then
        echo "Sertifikatet for $domain er gyldig og ikke tilbakekalt."
    else
        echo "Kunne ikke bestemme statusen til sertifikatet for $domain. Respons: $response"
    fi

    # Rydd opp midlertidige filer
    rm -f _cert.pem _issuer.pem
}

# Hovedprogrammet som kjører OCSP-sjekken
main() {
    if [ $# -lt 1 ] || [ $# -gt 2 ]; then
        echo "Bruk: $0 <domain:port> [--ftp | --smtp]"
        exit 1
    fi

    # Håndter inputparametere
    input=$1
    starttls=$2

    # Split domain og port fra input
    IFS=':' read -r domain port <<< "$input"
    
    # Sett standard port hvis ikke angitt
    if [ -z "$port" ]; then
        if [ "$starttls" = "--ftp" ]; then
            port=21
        elif [ "$starttls" = "--smtp" ]; then
            port=25
        else
            port=443
        fi
    fi

    # Sett starttls-verdi basert på parameter
    if [ "$starttls" = "--ftp" ]; then
        starttls="ftp"
    elif [ "$starttls" = "--smtp" ]; then
        starttls="smtp"
    else
        starttls=""
    fi

    # Kjør sjekk
    check_revocation_status "$domain" "$port" "$starttls"
}

main "$@"
