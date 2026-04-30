import ssl
import socket


def scan_ssl(domain):

    print(f"Starting SSL scan on {domain}...")

    result = {}

    try:

        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:

                cert = ssock.getpeercert()

                result["issuer"] = cert.get("issuer")
                result["subject"] = cert.get("subject")
                result["valid_from"] = cert.get("notBefore")
                result["valid_to"] = cert.get("notAfter")

        print("SSL scan finished.")

    except Exception as e:

        print("SSL scan failed:", e)

    return result