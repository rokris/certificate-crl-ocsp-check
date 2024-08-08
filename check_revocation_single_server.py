"""
Dette programmet sjekker statusen til et SSL-sertifikat for en gitt adresse ved å utføre flere
kontroller, inkludert
OCSP-sjekk og CRL-sjekk. Programmet kan også sammenligne sertifikatets serienummer med en liste
over kjente
serienumre lagret i en fil.

Funksjoner:
    - print_error(message): Skriver ut en feilmelding i rød tekst.
    - print_success(message): Skriver ut en suksessmelding i grønn tekst.
    - get_certificate(host, port): Henter SSL-sertifikatet fra en gitt vert og port.
    - extract_serial_number(cert): Ekstraherer serienummeret fra et gitt sertifikat.
    - format_serial_number(serial_number): Formaterer serienummeret som en heksadesimal streng.
    - get_crl_distribution_points(cert): Henter CRL-distribusjonspunktene fra et gitt sertifikat.
    - download_crl(url, debug): Laster ned CRL (Certificate Revocation List) fra en gitt URL og
      tolker den.
    - is_cert_revoked(crl, serial_number): Sjekker om et gitt sertifikat er tilbakekalt i en CRL.
    - check_ocsp_status(domain, debug): Sjekker OCSP-statusen for et gitt domene.
    - main(address, serial_list_file=None, debug=False): Hovedfunksjonen som utfører
      sertifikatvalidering, inkludert CRL- og OCSP-sjekker.

Bruk:
    python script.py <adresse> [fil med serienumre] [--debug]

Parametere:
    - <adresse>: Adressen til serveren som skal sjekkes (f.eks. "example.com"
      eller "https://example.com:443").
    - [fil med serienumre]: (Valgfritt) Fil som inneholder en liste over kjente serienumre som skal
      sjekkes mot sertifikatets serienummer.
    - [--debug]: (Valgfritt) Aktiverer detaljert feilsøkingsinformasjon under utførelsen.

Filformater:
1. **Serienummerliste-fil** (`serial_list_file`):
   - Format: Tekstfil (.txt)
   - Hver linje i filen inneholder et serienummer i heksadesimalt format. Eventuelle ekstra felt
     etter serienummeret blir ignorert.
   - Serienumrene kan være i store eller små bokstaver, men blir normalisert til store bokstaver
     i programmet.
   - Eksempel:
     ```
     0123456789ABCDEF0123456789ABCDEF
     ABCD1234EF567890ABCD1234EF567890
     ```

Utgangskoder:
    - 0: Suksess. Sertifikatet er gyldig og ikke tilbakekalt.
    - 1: Feil. En feil oppstod under sertifikatvalidering eller sjekkene indikerer at sertifikatet
      ikke er gyldig.
"""

import socket
import ssl
import sys

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
from ocspchecker import ocspchecker

# ANSI escape-koder for farge
RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"


def print_error(message):
    """Skriver ut en feilmelding i rød tekst."""
    print(f"{RED}{message}{RESET}")


def print_success(message):
    """Skriver ut en suksessmelding i grønn tekst."""
    print(f"{GREEN}{message}{RESET}")


def get_certificate(host, port):
    """
    Henter SSL-sertifikatet fra en gitt vert og port.

    Args:
        host (str): Vertens navn eller IP-adresse.
        port (int): Portnummeret som serveren lytter på.

    Returns:
        x509.Certificate: SSL-sertifikatet som er hentet fra serveren.
    """
    context = ssl.create_default_context()
    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            # Henter sertifikatet i DER-format (binærform)
            der_cert = ssock.getpeercert(binary_form=True)
            return x509.load_der_x509_certificate(der_cert, default_backend())


def extract_serial_number(cert):
    """
    Ekstraherer serienummeret fra et gitt sertifikat.

    Args:
        cert (x509.Certificate): SSL-sertifikatet.

    Returns:
        int: Serienummeret til sertifikatet.
    """
    return cert.serial_number


def format_serial_number(serial_number):
    """
    Formaterer serienummeret som en heksadesimal streng med store bokstaver.

    Args:
        serial_number (int): Serienummeret til sertifikatet.

    Returns:
        str: Formaterte serienummer som en 32-tegns heksadesimal streng.
    """
    return format(serial_number, "X").zfill(32).upper()


def get_crl_distribution_points(cert):
    """
    Henter CRL-distribusjonspunktene fra sertifikatet.

    Args:
        cert (x509.Certificate): SSL-sertifikatet.

    Returns:
        list: Liste over CRL-distribusjonspunkter (URLer) funnet i sertifikatet.
    """
    try:
        # Henter CRL-distribusjonspunkter fra sertifikatet
        cdp_extension = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        )
        return [
            point.full_name[0].value for point in cdp_extension.value if point.full_name
        ]
    except x509.ExtensionNotFound:
        return []


def download_crl(url, debug):
    """
    Laster ned CRL (Certificate Revocation List) fra en gitt URL og tolker den.

    Args:
        url (str): URL-en til CRL-filen.
        debug (bool): Aktiverer utskrift av feilsøkingsinformasjon.

    Returns:
        x509.CertificateRevocationList: Den nedlastede og tolkede CRL-filen.

    Raises:
        ValueError: Hvis CRL-filen ikke kan tolkes som verken PEM- eller DER-format.
    """
    if debug:
        print(f"Prøver å laste ned CRL fra URL: {url}")
    response = requests.get(url)
    response.raise_for_status()

    try:
        crl = x509.load_der_x509_crl(response.content, default_backend())
    except ValueError:
        try:
            crl = x509.load_pem_x509_crl(response.content, default_backend())
        except ValueError:
            raise ValueError(
                f"Kunne ikke tolke CRL fra {url}. "
                "Innholdet kan ikke være i PEM- eller DER-format."
            )

    if debug:
        print("CRL lastet ned og tolket.")

    return crl


def is_cert_revoked(crl, serial_number):
    """
    Sjekker om et gitt sertifikat er tilbakekalt i en CRL.

    Args:
        crl (x509.CertificateRevocationList): CRL-filen som skal sjekkes.
        serial_number (int): Serienummeret til sertifikatet.

    Returns:
        bool: True hvis sertifikatet er tilbakekalt, ellers False.
    """
    serial_number_hex = format_serial_number(serial_number)

    # Itererer gjennom alle tilbakekalte sertifikater i CRL
    for revoked_cert in crl:
        revoked_serial_number_hex = format_serial_number(revoked_cert.serial_number)
        if revoked_serial_number_hex == serial_number_hex:
            return True
    return False


def check_ocsp_status(domain, debug):
    """
    Sjekker OCSP-statusen for et gitt domene.

    Args:
        domain (str): Domenet som skal sjekkes.
        debug (bool): Aktiverer utskrift av feilsøkingsinformasjon.
    """
    try:
        ocsp_result = ocspchecker.get_ocsp_status(domain)
        if ocsp_result and isinstance(ocsp_result, list) and len(ocsp_result) > 0:
            # Anta at statusen er den første linjen og inneholder status
            status_line = next((line for line in ocsp_result if 'OCSP Status:' in line), None)
            if status_line:
                status = status_line.split(':', 1)[1].strip()
                if status.lower() == 'good':
                    print_success(f"OCSP Status: {status}")
                else:
                    print_error(f"OCSP Status: {status}")
            else:
                print_error("OCSP Status: Unknown")
        else:
            print_error("OCSP Status: Unknown")
    except Exception as e:
        print_error(f"Feil ved OCSP sjekking: {e}")


def main(address, serial_list_file=None, debug=False):
    """
    Hovedfunksjonen som utfører sertifikatvalidering, inkludert CRL- og OCSP-sjekker.

    Args:
        address (str): Adressen til serveren som skal sjekkes (f.eks. "example.com" eller
        "https://example.com:443").
        serial_list_file (str, optional): Fil som inneholder en liste over kjente serienumre for
        sammenligning.
        debug (bool, optional): Aktiverer detaljert feilsøkingsinformasjon. Default er False.
    """
    # Fjerner URL-skjema (f.eks. https://) hvis til stede
    if "://" in address:
        address = address.split("://")[1]

    # Sjekker om port er spesifisert
    if ":" in address:
        host, port = address.split(":")
        port = int(port)
    else:
        host = address
        port = 443  # Standard port for HTTPS

    try:
        cert = get_certificate(host, port)
    except Exception as e:
        print_error(
            f"Feil ved henting av sertifikat fra {address}. Kontrollér at adressen og "
            "porten er korrekte, og at serveren svarer."
        )
        print_error(f"Detaljer: {e}")
        sys.exit(1)

    # Ekstraherer og formaterer serienummeret til sertifikatet
    serial_number = extract_serial_number(cert)
    serial_number_hex = format_serial_number(serial_number)
    print(f"Sertifikatets serienummer (desimal): {serial_number}")
    print(f"Sertifikatets serienummer (heksadesimal): {serial_number_hex}")

    # Sjekker om sertifikatets serienummer finnes i en oppgitt fil
    if serial_list_file:
        try:
            with open(serial_list_file, 'r') as file:
                serials = [line.split()[0].strip().upper() for line in file.readlines()]

            if serial_number_hex in serials:
                print_error(f"Sertifikatets serienummer finnes i filen: {serial_list_file}")
            else:
                print_success(f"Sertifikatets serienummer finnes ikke i filen: {serial_list_file}")
        except FileNotFoundError:
            print_error(f"Feil: Filen '{serial_list_file}' finnes ikke.")
            sys.exit(1)

    # Henter CRL-distribusjonspunkter og sjekker om sertifikatet er tilbakekalt
    crl_urls = get_crl_distribution_points(cert)
    if not crl_urls:
        print_error("Ingen CRL-distribusjonspunkter funnet i sertifikatet.")
    else:
        for url in crl_urls:
            try:
                crl = download_crl(url, debug)
                if is_cert_revoked(crl, serial_number):
                    print_error("Sertifikatet har blitt trukket tilbake i CRL.")
                    sys.exit(1)
                else:
                    print_success("Sertifikatet er ikke trukket tilbake ifølge CRL.")
            except Exception as e:
                print_error(f"Kunne ikke laste ned eller analysere CRL fra {url}.")
                print_error(f"Detaljer: {e}")
                continue

    # Kall til OCSP-sjekk
    check_ocsp_status(host, debug)


if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 4:
        print_error("Bruk: python script.py <adresse> [fil med serienumre] [--debug]")
        sys.exit(1)

    address = sys.argv[1]
    serial_list_file = sys.argv[2] if len(sys.argv) == 3 and sys.argv[2] != '--debug' else None
    debug = (
        (len(sys.argv) == 3 and sys.argv[2] == '--debug') or
        (len(sys.argv) == 4 and sys.argv[3] == '--debug')
    )

    # Kjører hovedfunksjonen
    main(address, serial_list_file, debug)
