import socket
import ssl
import sys

import certifi
import colorama
import requests
from colorama import Fore, Style
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import ExtensionOID
from ocspchecker import ocspchecker

# Initialiser colorama
colorama.init(autoreset=True)

# ANSI escape-koder for farge
RED = Fore.RED
GREEN = Fore.GREEN
RESET = Style.RESET_ALL


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
    # Sett opp SSL-konteksten
    context = ssl.create_default_context(cafile=certifi.where())
    context.minimum_version = ssl.TLSVersion.TLSv1_2  # Håndheve minimum TLSv1.2
    context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3  # Deaktiver SSLv2 og SSLv3
    context.verify_mode = ssl.CERT_REQUIRED  # Krev serversertifikatvalidering
    context.check_hostname = True  # Verifiser vertsnavnet mot sertifikatet

    # Opprett og koble til socket med SSL-kontekst
    with context.wrap_socket(socket.socket(), server_hostname=host) as s:
        s.connect((host, port))
        # Hent og konverter sertifikatet til PEM-format
        cert_der = s.getpeercert(binary_form=True)
        cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)

    # Last inn sertifikatet ved hjelp av cryptography-biblioteket
    cert = load_pem_x509_certificate(cert_pem.encode(), default_backend())

    return cert


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
        except ValueError as err:
            raise ValueError(
                f"Kunne ikke tolke CRL fra {url}. Innholdet kan ikke være i PEM- eller DER-format."
            ) from err

    if debug:
        print("CRL lastet ned og tolket.")

    return crl


def is_cert_revoked(crl, serial_number, debug):
    """
    Sjekker om et gitt sertifikat er tilbakekalt i en CRL.
    Args:
        crl (x509.CertificateRevocationList): CRL-filen som skal sjekkes.
        serial_number (int): Serienummeret til sertifikatet.
        debug (bool): Aktiverer utskrift av feilsøkingsinformasjon.
    Returns:
        bool: True hvis sertifikatet er tilbakekalt, ellers False.
    """
    serial_number_hex = format_serial_number(serial_number)
    if debug:
        print(f"Serienummer som sjekkes (heksadesimal): {serial_number_hex}")

    # Itererer gjennom alle tilbakekalte sertifikater i CRL
    for revoked_cert in crl:
        revoked_serial_number_hex = format_serial_number(revoked_cert.serial_number)
        if debug:
            print(f"Tilbakekalt serienummer i CRL: {revoked_serial_number_hex}")

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
            status_line = next(
                (line for line in ocsp_result if "OCSP Status:" in line), None
            )
            if status_line:
                status = status_line.split(":", 1)[1].strip()
                if status != "GOOD":
                    print_error(f"OCSP Status: {status}")
                else:
                    print_success(f"OCSP Status: {status}")
            else:
                print_error("OCSP Status: Unknown")
        else:
            print_error("OCSP Status: Unknown")
    except Exception as exc:
        print_error(f"Feil ved OCSP sjekking: {exc}")


def process_address(address, crlliste=None, debug=False):
    """
    Prosesserer en enkel serveradresse ved å hente sertifikatet, sjekke serienummeret,
    laste ned CRL og utføre OCSP-sjekk.
    Args:
        address (str): Serveradressen (f.eks. "example.com" eller "https://example.com:443").
        crlliste (str, optional): Fil som inneholder en liste over kjente serienumre
        for sammenligning.
        debug (bool, optional): Aktiverer detaljert feilsøkingsinformasjon. Default er False.
    """
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
    except (socket.error, ssl.SSLError) as exc:
        print_error(
            f"Feil ved henting av sertifikat fra {address}. Kontrollér at adressen og "
            f"porten er korrekte, og at serveren svarer."
        )
        print(f"Detaljer: {exc}")
        return

    # Ekstraherer og formaterer serienummeret til sertifikatet
    serial_number = extract_serial_number(cert)
    serial_number_hex = format_serial_number(serial_number)
    print(f"Sertifikatets serienummer (desimal): {serial_number}")
    print(f"Sertifikatets serienummer (heksadesimal): {serial_number_hex}")

    # Sjekker om sertifikatets serienummer finnes i en oppgitt fil
    if crlliste:
        try:
            with open(crlliste, "r", encoding="utf-8") as file:
                serials = [line.split()[0].strip().upper() for line in file.readlines()]

            if serial_number_hex in serials:
                print_error(f"Sertifikatets serienummer finnes i filen: {crlliste}")
            else:
                print_success(
                    f"Sertifikatets serienummer finnes ikke i filen: {crlliste}"
                )
        except FileNotFoundError:
            print_error(f"Feil: Filen '{crlliste}' finnes ikke.")
            return

    # Henter CRL-distribusjonspunkter og sjekker om sertifikatet er tilbakekalt
    crl_urls = get_crl_distribution_points(cert)
    if not crl_urls:
        print_error("Ingen CRL-distribusjonspunkter funnet i sertifikatet.")
    else:
        for url in crl_urls:
            try:
                crl = download_crl(url, debug)
                if is_cert_revoked(crl, serial_number, debug):
                    print_error(
                        f"Sertifikatet har blitt trukket tilbake i CRL fra {url}."
                    )
                    return
                else:
                    print_success(
                        f"Sertifikatet er ikke trukket tilbake ifølge CRL fra {url}."
                    )
            except ValueError as exc:
                print_error(f"Kunne ikke laste ned eller analysere CRL fra {url}.")
                print(f"Detaljer: {exc}")
                continue

    # Utfør OCSP-sjekk
    check_ocsp_status(host, debug)


def main(serverliste=None, crlliste=None, debug=False):
    """
    Hovedfunksjonen som leser serveradresser fra en fil eller direkte fra kommando-linjen.
    Args:
        serverliste (str, optional): Fil som inneholder en liste over serveradresser
        som skal prosesseres.
        crlliste (str, optional): Fil som inneholder kjente serienumre for
        sammenligning.
        debug (bool, optional): Aktiverer detaljert feilsøkingsinformasjon. Default er False.
        help (Denne siden)
    """
    if serverliste:
        try:
            with open(serverliste, "r", encoding="utf-8") as file:
                addresses = [line.strip() for line in file.readlines()]
        except FileNotFoundError:
            print_error(f"Feil: Filen '{serverliste}' finnes ikke.")
            sys.exit(1)
    else:
        # Hvis ingen serverliste er spesifisert, ta første argument som adresse
        if len(sys.argv) > 1:
            addresses = [sys.argv[1]]
        else:
            print_error("Feil: Ingen serveradresse eller serverliste spesifisert.")
            sys.exit(1)

    for address in addresses:
        print(f"Sjekker server: {address}")
        process_address(address, crlliste, debug)
        print("-" * 50)


if __name__ == "__main__":
    # Sjekk konteksten (kjører som PyInstaller eller Python-skript)
    is_pyinstaller_executable = getattr(sys, "frozen", False)

    # Juster sys.argv hvis det kjører som en PyInstaller-eksekverbar fil
    if is_pyinstaller_executable:
        # Fjern det første argumentet som er navnet på den eksekverbare filen
        args = sys.argv[1:]
    else:
        args = sys.argv[1:]

    if len(sys.argv) <= 1 or len(sys.argv) > 6:
        print(
            "Bruk: check_revocation --serverlist <fil> --crl-list <fil> [--debug] [--help]"
        )
        sys.exit(1)

    serverliste = None
    crlliste = None
    debug = False

    # Parse kommando linje argumenter
    args_iter = iter(args)
    for arg in args_iter:
        if arg == "--help":
            print(
                """

Programmet brukes for å sjekke om sertifikatet til en host er trukket tilbake.

Det tar inn serveradresser fra en fil eller direkte fra kommando-linjen.

Argumenter:

--serverliste (str, optional): Fil som inneholder en liste over serveradresser som skal prosesseres.

--crl-liste (str, optional): Fil som inneholder kjente serienumre for sammenligning.

--debug (bool, optional): Aktiverer detaljert feilsøkingsinformasjon. Default er False.

--hjelp (Denne siden)

Syntax: check_revocation --serverlist <fil> --crl-list <fil> [--debug] [--help]
            """
            )
        elif arg == "--serverliste":
            serverliste = next(args_iter, None)
        elif arg == "--crl-liste":
            crlliste = next(args_iter, None)
        elif arg == "--debug":
            debug = True

    # Kjører hovedfunksjonen
    if not arg == "--help":
        main(serverliste, crlliste, debug)
