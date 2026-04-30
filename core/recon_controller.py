import threading
import uuid

from modules.whois_scan import scan_whois
from modules.port_scan import scan_ports
from modules.dns_scan import scan_dns
from modules.subdomain_scan import scan_subdomains
from modules.http_scan import scan_http
from modules.dir_scan import scan_directories
from modules.header_scan import scan_headers
from modules.ssl_scan import scan_ssl
from modules.robots_scan import scan_robots

from reports.report_generator import generate_report

def normalize_headers(headers):
    normalized = {}

    for h, v in headers.items():

        if isinstance(v, dict) and "status" in v:
            normalized[h] = v

        elif isinstance(v, str):
            if "Missing" in v:
                normalized[h] = {
                    "status": "Missing",
                    "risk": "UNKNOWN"
                }
            else:
                normalized[h] = {
                    "status": "Present",
                    "risk": None
                }

        else:
            normalized[h] = {
                "status": "Unknown",
                "risk": None
            }

    return normalized


def run_scan(target):
    scan_id = str(uuid.uuid4())
    
    results = {}

    def whois_thread():
        print("Running WHOIS scan...")
        results["whois"] = scan_whois(target)

    def port_thread():
        print("Running PORT scan...")
        results["ports"] = scan_ports(target)

    def dns_thread():
        print("Running DNS scan...")
        results["dns"] = scan_dns(target)

    def subdomain_thread():
        print("Running SUBDOMAIN scan...")
        results["subdomains"] = scan_subdomains(target)

    def http_thread():
        print("Running HTTP scan...")
        results["http"] = scan_http(target)

    def dir_thread():
        print("Running DIRECTORY scan...")
        results["directories"] = scan_directories(target)

    def header_thread():
        print("Running HEADER scan...")
        results["headers"] = scan_headers(target)

    def ssl_thread():
        print("Running SSL scan...")
        results["ssl"] = scan_ssl(target)

    def robots_thread():
        print("Running ROBOTS scan...")
        results["robots"] = scan_robots(target)


    threads = [
        threading.Thread(target=whois_thread),
        threading.Thread(target=port_thread),
        threading.Thread(target=dns_thread),
        threading.Thread(target=subdomain_thread),
        threading.Thread(target=http_thread),
        threading.Thread(target=dir_thread),
        threading.Thread(target=header_thread),
        threading.Thread(target=ssl_thread),
        threading.Thread(target=robots_thread)
    ]


    for t in threads:
        t.start()
        
    for t in threads:
        t.join()

    if "headers" in results:
        results["headers"] = normalize_headers(results["headers"])

    print(results)

    pdf_path = generate_report(target, results)

    return {
        "results": results,
        "pdf_path": pdf_path,
        "scan_id": scan_id,
        "target": target,
        "status": "Completed"
    }