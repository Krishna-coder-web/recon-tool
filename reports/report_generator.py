import os
from fpdf import FPDF

def generate_summary(results):

    risky_ports = []
    summary = []

    # Headers
    header_data = results.get("headers", {})
    
    if "headers" in header_data:
        headers = header_data["headers"]
    else:
        headers = header_data
        
    missing = []
    present = []
    required_headers = ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-XSS-Protection", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]
    if headers:
        for h in required_headers:
            if h in headers:
                present.append(h.replace("-", " ").title())
            else:
                missing.append(h.replace("-", " ").title())
        if missing:
            summary.append(f"Missing security headers: {', '.join(missing)}")
        else:
            summary.append("All critical security headers are present")
            
    # Ports
    ports = results.get("ports", [])
    if ports:
        summary.append(f"Open ports detected: {', '.join(map(str, ports))}")
        
        risky_ports =[]
        for p in ports:
            if p in [21, 22, 23, 25, 26, 3306, 3389]:
                risky_ports.append(p)
        if risky_ports:
            summary.append(f"High-risk ports open: {', '.join(map(str, risky_ports))}")

    # Robots
    robots = results.get("robots", {})
    sensitive_found = False
    for entry in robots.get("entries", []):
        if any(k in entry.lower() for k in ["admin", "login", "dashboard", "config", "backup", "auth"]):
            sensitive_found = True
            break
    if sensitive_found:
        summary.append("Sensitive paths exposed in robots.txt")
    else:
        summary.append("robots.txt found but no sensitive entries detected")
        

    # Directories
    dirs = results.get("directories", [])
    if dirs:
        sensitive_dir=[]
        
        for d in dirs:
            if any(k in d.lower() for k in ["admin", "login", "dashboard", "config", "backup", "auth"]):
                sensitive_dir.append(d)
        if sensitive_dir:
            summary.append(f"{len(sensitive_dir)} sensitive paths discovered")
        else:
            summary.append("No sensitive directories exposed")
            
    # Risk scoring
    risk_score = 0

    # Headers
    risk_score += len(missing)

    # Ports
    risk_score += len(risky_ports) * 3

    # Robots
    if robots.get("entries"):
        risk_score += 3

    # Directories
    if dirs:
        risk_score += 2

    # Level
    if risk_score >= 30:
        level = "HIGH"
    elif risk_score >= 10:
        level = "MEDIUM"
    else:
        level = "LOW"

    summary.insert(0, f"Overall Risk Assessment: {level} (Score: {risk_score})")

    return summary,{
        "missing": missing,
        "risky_ports": risky_ports,
        "robots": robots,
        "dirs": dirs,
        "headers_present": present,
        "headers_missing": missing
    }

def generate_report(target, results):

    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Title
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, f"Reconnaissance Report: {target}", ln=True)
    pdf.ln(5)

    # SUMMARY
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Summary", ln=True)

    pdf.set_font("Arial", "", 11)
    summary, findings = generate_summary(results)

    if summary:
        for line in summary:
            pdf.multi_cell(0, 8, f"- {line}")
    else:
        pdf.multi_cell(0, 8, "No significant findings")

    pdf.ln(5)

    # WHOIS
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "WHOIS Information", ln=True)

    pdf.set_font("Arial", "", 11)
    whois_data = results.get("whois", {})

    if isinstance(whois_data, dict):
        seen = set()

        for key, value in whois_data.items():

            if key in seen:
                continue
            seen.add(key)

            if isinstance(value, list):
                cleaned = []
                for v in value:
                    if hasattr(v, "strftime"):
                        cleaned.append(v.strftime("%Y-%m-%d"))
                    else:
                        cleaned.append(str(v))

                value = ", ".join(list(set(cleaned)))

            elif hasattr(value, "strftime"):
                value = value.strftime("%Y-%m-%d")

            pdf.multi_cell(0, 8, f"{key}: {value}")
    else:
        pdf.multi_cell(0, 8, "No WHOIS data found")
        
    pdf.ln(5)

    # DNS
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "DNS Records", ln=True)

    pdf.set_font("Arial", "", 11)
    dns_data = results.get("dns", [])

    if dns_data:
        for record in dns_data:
            pdf.multi_cell(0, 8, str(record))
    else:
        pdf.multi_cell(0, 8, "No DNS data found")

    pdf.ln(5)

    # PORTS
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Open Ports", ln=True)

    pdf.set_font("Arial", "", 11)
    ports = results.get("ports", [])

    if ports:
        for port in ports:
            pdf.multi_cell(0, 8, f"Port {port} is open")
    else:
        pdf.multi_cell(0, 8, "No open ports detected")

    pdf.ln(5)

    # SUBDOMAINS
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Discovered Subdomains", ln=True)

    pdf.set_font("Arial", "", 11)
    subs = results.get("subdomains", [])

    if subs:
        for sub in subs:
            pdf.multi_cell(0, 8, sub)
    else:
        pdf.multi_cell(0, 8, "No subdomains discovered")

    pdf.ln(5)

    # DIRECTORIES
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Directory Discovery", ln=True)

    pdf.set_font("Arial", "", 11)
    dirs = results.get("directories", [])

    if dirs:
        for d in dirs:
            pdf.multi_cell(0, 8, d)
    else:
        pdf.multi_cell(0, 8, "No directories discovered")

    pdf.ln(5)

    # HEADERS
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "HTTP Security Header Analysis", ln=True)

    pdf.set_font("Arial", "", 11)
    header_data = results.get("headers", {})
    if "headers" in header_data:
        headers = header_data["headers"]
    else:
        headers = header_data

    headers_missing = findings.get("headers_missing", [])
    headers_present = findings.get("headers_present", [])
    if headers_present:
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 8, "Present Headers:", ln=True)
        pdf.set_font("Arial", "", 11)
        for h in headers_present:
            pdf.multi_cell(0, 8, f"- {h}")
        pdf.ln(2)
        
    if headers_missing:
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 8, "Missing Headers:", ln=True)
        pdf.set_font("Arial", "", 11)
        for h in headers_missing:
            pdf.multi_cell(0, 8, f"- {h}")
    else:
        pdf.multi_cell(0, 8, "All critical security headers are present")    
    

    # SSL
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "SSL Certificate Information", ln=True)

    pdf.set_font("Arial", "", 11)
    ssl_data = results.get("ssl", {})

    def extract_value(field):
        try:
            return field[0][0][1]
        except:
            return "Unknown"

    if ssl_data:
        issuer = extract_value(ssl_data.get("issuer"))
        subject = extract_value(ssl_data.get("subject"))
        valid_from = ssl_data.get("valid_from", "Unknown")
        valid_to = ssl_data.get("valid_to", "Unknown")

        pdf.multi_cell(0, 8, f"Issuer: {issuer}")
        pdf.multi_cell(0, 8, f"Domain: {subject}")
        pdf.multi_cell(0, 8, f"Valid From: {valid_from}")
        pdf.multi_cell(0, 8, f"Valid To: {valid_to}")
    else:
        pdf.multi_cell(0, 8, "No SSL information found")

    pdf.ln(5)
    
    # ROBOTS
    SENSITIVE_KEYWORDS = [
        "admin", "login", "dashboard", "config",
        "backup", "auth"
    ]

    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "robots.txt Analysis", ln=True)

    pdf.set_font("Arial", "", 11)
    robots_data = results.get("robots", {})

    base_url = results.get("final_url", f"https://{target}")

    if robots_data.get("found"):

        entries = robots_data.get("entries", [])
        filtered = []

        for entry in entries:
            if ":" not in entry:
                continue

            path = entry.split(":", 1)[1].strip()

            if any(k in path.lower() for k in SENSITIVE_KEYWORDS):
                if not path.startswith("/"):
                    path = "/" + path
                full_url = f"{base_url.rstrip('/')}{path}"
                filtered.append(full_url)

        if filtered:
            for url in filtered[:20]:
                pdf.multi_cell(0, 8, f"{url} (Potentially Sensitive)")

            if len(filtered) > 20:
                pdf.multi_cell(0, 8, f"...and {len(filtered) - 20} more entries hidden")

        else:
            pdf.multi_cell(0, 8, "No high-risk entries found in robots.txt")

    else:
        pdf.multi_cell(0, 8, "robots.txt not found")
    pdf.ln(5)

    # RECOMMENDATIONS
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Recommendations", ln=True)

    pdf.set_font("Arial", "", 11)

    recommendations = []

    if findings.get("headers_missing"):
        recommendations.append("Implement missing security headers like CSP, HSTS, X-Frame-Options")

    if findings["risky_ports"]:
        recommendations.append("Close or restrict access to high-risk ports")

    if any(k in entry.lower() for entry in findings["robots"].get("entries", []) for k in ["admin", "login", "config", "backup"]):
        recommendations.append("Avoid exposing sensitive paths in robots.txt")

    if findings["dirs"]:
        recommendations.append("Restrict access to sensitive directories")

    if recommendations:
        for rec in recommendations:
            pdf.multi_cell(0, 8, f"- {rec}")
    else:
        pdf.multi_cell(0, 8, "No immediate security recommendations")

    pdf.ln(5)

    # SAVE
    report_dir = os.path.join("generated_reports")

    os.makedirs(report_dir, exist_ok=True)

    safe_target = target.replace("http://", "").replace("https://", "").replace("/", "_")
    filename = os.path.join(report_dir, f"{safe_target}_report.pdf")

    pdf.output(filename)

    print(f"Report saved as {filename}")
    
    return filename