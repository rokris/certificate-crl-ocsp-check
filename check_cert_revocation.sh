#!/bin/bash

# Skriptet krever følgende for å kunne kjøres:
# - Unix-lignende OS som Linux eller macOS med Bash-skall.
# - `openssl`-verktøyet for håndtering av SSL-sertifikater og OCSP-sjekker.
# - `wget`-verktøyet for nedlasting av utstedersertifikater.
# - Internettforbindelse for å hente sertifikater og kommunisere med OCSP-servere.
# - Tilgangsrettigheter for å kjøre `openssl`, `wget` og for å opprette/slette midlertidige filer.
# - Minst én inngangsparameter (`domain:port`) må oppgis ved kjøring.
# - Opsjonelle parametere: `--web`, `--ftp`, `--smtp` for protokollvalg og `--showcert` for å vise sertifikatdetaljer.
# - Domenenavn/IP-adresser og porter må være korrekte og serverne må være tilgjengelige over nettverket.
# - Skriptet oppretter midlertidige filer (`_cert.pem`, `_issuer.pem`) i arbeidskatalogen og krever tilstrekkelig diskplass og rettigheter.

# Funksjon for å fargelegge meldinger
color_echo() {
	local color=$1
	local message=$2
	local reset="\033[0m"

	case $color in
	red)
		echo -e "\033[31m$message$reset"
		;;
	green)
		echo -e "\033[32m$message$reset"
		;;
	*)
		echo "$message" # Uten farge
		;;
	esac
}

# Funksjon for å hente sertifikatet fra en gitt URL, WEB, FTP eller SMTP
get_certificate() {
	local domain=$1
	local port=$2
	local protocol=$3

	case "$protocol" in
	ftp)
		echo | openssl s_client -connect "$domain:$port" -starttls ftp 2>/dev/null | openssl x509
		;;
	smtp)
		echo | openssl s_client -connect "$domain:$port" -starttls smtp 2>/dev/null | openssl x509
		;;
	web)
		echo | openssl s_client -connect "$domain:$port" -servername "$domain" 2>/dev/null | openssl x509
		;;
	esac
}

# Funksjon for å vise sertifikatdetaljer
show_certificate() {
	local domain=$1
	local port=$2
	local protocol=$3

	# Hent sertifikat
	cert=$(get_certificate "$domain" "$port" "$protocol")

	if [ -z "$cert" ]; then
		color_echo "red" "Kunne ikke hente sertifikatet for $domain."
		return 1
	fi

	# Skriv ut sertifikatdetaljer
	echo "Sertifikatdetaljer for $domain:$port:"
	echo "$cert" | openssl x509 -text -noout
}

# Funksjon for å sjekke om sertifikatet er tilbakekalt via OCSP
check_revocation_status() {
	local domain=$1
	local port=$2
	local protocol=$3

	# Hent sertifikat
	cert=$(get_certificate "$domain" "$port" "$protocol")

	if [ -z "$cert" ]; then
		color_echo "red" "Kunne ikke hente sertifikatet for $domain."
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
		color_echo "red" "Kunne ikke finne OCSP URL i sertifikatet."
		return 1
	fi

	# Prøv å hente utstederens sertifikat URL fra "Authority Information Access" (AIA)
	issuer_url=$(echo "$cert" | openssl x509 -text -noout | grep -A1 "CA Issuers" | grep -o 'http[^ ]*')

	if [ -z "$issuer_url" ]; then
		color_echo "red" "Kunne ikke finne utstederens sertifikat URL."
		return 1
	fi

	# Last ned utstederens sertifikat
	wget -q -O _issuer.pem "$issuer_url"
	if [ ! -s _issuer.pem ]; then
		color_echo "red" "Kunne ikke laste ned eller fant ikke et gyldig utstedersertifikat."
		return 1
	fi

	# Sjekk sertifikatet mot OCSP
	echo "$cert" >_cert.pem
	response=$(openssl ocsp -issuer _issuer.pem -cert _cert.pem -url "$ocsp_url" -CAfile _issuer.pem -text 2>&1)

	if echo "$response" | grep -q "Cert Status: revoked"; then
		color_echo "red" "Sertifikatet for $domain er tilbakekalt!"
	elif echo "$response" | grep -q "Cert Status: good"; then
		color_echo "green" "Sertifikatet for $domain er gyldig og ikke tilbakekalt."
	else
		color_echo "red" "Kunne ikke bestemme statusen til sertifikatet for $domain. Respons: $response"
	fi

	# Rydd opp midlertidige filer
	rm -f _cert.pem _issuer.pem
}

# Hovedprogrammet som kjører OCSP-sjekken
main() {
	if [ $# -lt 1 ] || [ $# -gt 3 ]; then
		echo "Bruk: $0 <domain:port> [--web | --ftp | --smtp] [--showcert]"
		exit 1
	fi

	# Håndter inputparametere
	input=$1
	protocol=$2
	showcert=$3

	# Split domain og port fra input
	IFS=':' read -r domain port <<<"$input"

	# Sett standard port hvis ikke angitt
	if [ -z "$port" ]; then
		if [ "$protocol" = "--ftp" ]; then
			port=21
		elif [ "$protocol" = "--smtp" ]; then
			port=25
		else
			port=443
		fi
	fi

	# Sett protocol-verdi basert på parameter
	if [ "$protocol" = "--ftp" ]; then
		protocol="ftp"
	elif [ "$protocol" = "--smtp" ]; then
		protocol="smtp"
	else
		protocol="web"
	fi

	if [ "$showcert" = "--showcert" ]; then
		show_certificate "$domain" "$port" "$protocol"
		check_revocation_status "$domain" "$port" "$protocol"
	else
		check_revocation_status "$domain" "$port" "$protocol"
	fi
}

main "$@"
