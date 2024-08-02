import sys
import socket
import ssl
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
from ocspchecker import ocspchecker

def get_certificate(host, port):
    context = ssl.create_default_context()
    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            der_cert = ssock.getpeercert(binary_form=True)
            return x509.load_der_x509_certificate(der_cert, default_backend())

def extract_serial_number(cert):
    return cert.serial_number

def format_serial_number(serial_number):
    return format(serial_number, 'X').zfill(32).upper()

def get_crl_distribution_points(cert):
    try:
        cdp_extension = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        return [point.full_name[0].value for point in cdp_extension.value if point.full_name]
    except x509.ExtensionNotFound:
        return []

def download_crl(url, debug):
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
            raise ValueError(f"Kunne ikke tolke CRL fra {url}. Innholdet kan ikke være i PEM- eller DER-format.")
    
    if debug:
        print("CRL lastet ned og tolket.")
    
    return crl

def is_cert_revoked(crl, serial_number):
    serial_number_hex = format_serial_number(serial_number)
    if debug:
        print(f"Serienummer som sjekkes (heksadesimal): {serial_number_hex}")

    for revoked_cert in crl:
        revoked_serial_number_hex = format_serial_number(revoked_cert.serial_number)
        if debug:
            print(f"Tilbakekalt serienummer i CRL: {revoked_serial_number_hex}")

        if revoked_serial_number_hex == serial_number_hex:
            return True
    return False

def check_ocsp_status(domain, debug):
    try:
        # Få OCSP-status for domenet
        ocsp_result = ocspchecker.get_ocsp_status(domain)
        if ocsp_result and isinstance(ocsp_result, list) and len(ocsp_result) > 0:
            # Anta at statusen er den første linjen og inneholder status
            status_line = next((line for line in ocsp_result if 'OCSP Status:' in line), None)
            if status_line:
                status = status_line.split(':', 1)[1].strip()  # Henter statusen etter 'OCSP Status:'
                print(f"OCSP Status: {status}")
            else:
                print("OCSP Status: Unknown")
        else:
            print("OCSP Status: Unknown")
    except Exception as e:
        print(f"Feil ved OCSP sjekking: {e}")

def main(address, serial_list_file=None, debug=False):
    if "://" in address:
        address = address.split("://")[1]

    if ":" in address:
        host, port = address.split(":")
        port = int(port)
    else:
        host = address
        port = 443

    try:
        cert = get_certificate(host, port)
    except Exception as e:
        print(f"Feil ved henting av sertifikat fra {address}. Kontrollér at adressen og porten er korrekte, og at serveren svarer.")
        print(f"Detaljer: {e}")
        sys.exit(1)

    serial_number = extract_serial_number(cert)
    serial_number_hex = format_serial_number(serial_number)
    print(f"Sertifikatets serienummer (desimal): {serial_number}")
    print(f"Sertifikatets serienummer (heksadesimal): {serial_number_hex}")

    if serial_list_file:
        try:
            with open(serial_list_file, 'r') as file:
                serials = [line.split()[0].strip().upper() for line in file.readlines()]
                
            if serial_number_hex in serials:
                print(f"Sertifikatets serienummer finnes i filen: {serial_list_file}")
            else:
                print(f"Sertifikatets serienummer finnes ikke i filen: {serial_list_file}")
        except FileNotFoundError:
            print(f"Feil: Filen '{serial_list_file}' finnes ikke.")
            sys.exit(1)

    crl_urls = get_crl_distribution_points(cert)
    if not crl_urls:
        print("Ingen CRL-distribusjonspunkter funnet i sertifikatet.")
    else:
        for url in crl_urls:
            try:
                crl = download_crl(url, debug)
                if is_cert_revoked(crl, serial_number):
                    print("Sertifikatet har blitt trukket tilbake i CRL.")
                    sys.exit(1)
                else:
                    print("Sertifikatet er ikke trukket tilbake ifølge CRL.")
            except Exception as e:
                print(f"Kunne ikke laste ned eller analysere CRL fra {url}.")
                print(f"Detaljer: {e}")
                continue

    # Kall til OCSP sjekk
    check_ocsp_status(host, debug)

if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 4:
        print("Bruk: python script.py <adresse> [fil med serienumre] [--debug]")
        sys.exit(1)
    
    address = sys.argv[1]
    serial_list_file = sys.argv[2] if len(sys.argv) == 3 and sys.argv[2] != '--debug' else None
    debug = len(sys.argv) == 3 and sys.argv[2] == '--debug' or len(sys.argv) == 4 and sys.argv[3] == '--debug'

    main(address, serial_list_file, debug)
