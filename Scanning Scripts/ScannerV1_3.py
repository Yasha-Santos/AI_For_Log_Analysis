import requests
import base64
from datetime import datetime
import geoip2.database
import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

# =====================================================================
# CONFIGURATION - INSERT API KEYS HERE
# =====================================================================
ABUSEIPDB_API_KEY = "231c4a9e71b145ec686d83d9002ed73f77d33215e81a7a859bd3076718eb6965220afc4d5195cc5b"
VIRUSTOTAL_API_KEY = "270a570af4daa177239a4b5a656d0ecd2654fc48ff3374f01d23a31db1b8b119"
ALIENVAULT_API_KEY = "cf208987d93d8363ba2164f21d6f5c4908c48d265e662a7bec2ed7460680da1c"

# Global session cache to store scan details for the PDF summary
scan_history = []


# =====================================================================
# CORE THREAT INTEL FUNCTIONS
# =====================================================================

def check_ip_consensus(ip_address, abuse_key, otx_key):
    """Queries both AbuseIPDB and AlienVault OTX for a unified consensus report."""
    if not ip_address: return

    print(f"\n[+] [Consensus Scan] Evaluating IP: {ip_address}...")

    # 1. AbuseIPDB Check
    abuse_score = 0
    abuse_reports = 0
    abuse_summary = "Clean or no recent reports."
    abuse_malicious = False

    if abuse_key and abuse_key != "your_abuseipdb_api_key_here":
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            headers = {'Accept': 'application/json', 'Key': abuse_key}
            resp = requests.get(url, headers=headers,
                                params={'ipAddress': ip_address, 'maxAgeInDays': '90', 'verbose': True})
            resp.raise_for_status()
            data = resp.json()['data']

            abuse_score = data['abuseConfidenceScore']
            abuse_reports = data['totalReports']
            abuse_malicious = abuse_score > 50

            if abuse_malicious and abuse_reports > 0:
                recent_reports = data['reports'][:2]
                abuse_summary = " | ".join([f"[{r['reportedAt'][:10]}] {r['comment']}" for r in recent_reports])

        except requests.exceptions.RequestException as e:
            abuse_summary = f"API Error: {e}"
    else:
        abuse_summary = "API Key Missing."

    # 2. AlienVault OTX Check
    otx_pulses = 0
    otx_summary = "Clean or not tracked."
    otx_malicious = False

    if otx_key and otx_key != "your_alienvault_otx_api_key_here":
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"
            headers = {'X-OTX-API-KEY': otx_key}
            resp = requests.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()

            otx_pulses = data.get('pulse_info', {}).get('count', 0)
            otx_malicious = otx_pulses > 0

            if otx_malicious:
                pulses = data['pulse_info']['pulses'][:2]
                otx_summary = f"Flagged in feeds: {', '.join([p['name'] for p in pulses])}"

        except requests.exceptions.RequestException as e:
            otx_summary = f"API Error: {e}"
    else:
        otx_summary = "API Key Missing."

    # Print Console Results
    print(f"--- Consensus Results ---")
    print(
        f"AbuseIPDB: {'⚠️ Malicious' if abuse_malicious else '✅ Clean'} (Score: {abuse_score}%, Reports: {abuse_reports})")
    print(f"AlienVault OTX: {'⚠️ Malicious' if otx_malicious else '✅ Clean'} (Threat Pulses: {otx_pulses})")

    if abuse_malicious: print(f"AbuseIPDB Context: {abuse_summary[:80]}...")
    if otx_malicious: print(f"OTX Context: {otx_summary[:80]}...")

    # Log Combined Result for PDF
    is_dangerous = abuse_malicious or otx_malicious

    scan_history.append({
        "type": "IP Consensus (AbuseIPDB + OTX)",
        "target": ip_address,
        "status": "MALICIOUS / FLAGGED" if is_dangerous else "CLEAN",
        "metrics": f"AbuseIPDB Score: {abuse_score}% | OTX Pulses: {otx_pulses}",
        "summary": f"<b>AbuseIPDB:</b> {abuse_summary}<br/><b>AlienVault:</b> {otx_summary}"
    })


def check_ip_offline_geo(ip_address, db_path="GeoLite2-Country.mmdb"):
    """
    Performs an offline IP geolocation lookup using a local MaxMind Country database.
    Requires no internet connection or API keys.
    """
    if not ip_address: return

    print(f"\n[+] [Offline Geo] Looking up country for: {ip_address}...")

    if not os.path.exists(db_path):
        print(f"[-] Error: Offline database '{db_path}' not found.")
        print("    Please download the GeoLite2-Country.mmdb file from MaxMind and place it in this directory.")
        return

    try:
        # Open the local database file
        with geoip2.database.Reader(db_path) as reader:
            # Note: We must use .country() instead of .city() for this specific database
            response = reader.country(ip_address)

            country = response.country.name or "Unknown Country"
            iso = response.country.iso_code or "??"

            print(f"✅ Location: {country} ({iso})")

            # Log to PDF session history
            scan_history.append({
                "type": "Offline Geolocation",
                "target": ip_address,
                "status": "LOCATED",
                "metrics": f"ISO: {iso}",
                "summary": f"Country: {country}"
            })

    except geoip2.errors.AddressNotFoundError:
        print(f"[-] Address {ip_address} is not in the offline database (Likely a local/private IP).")
    except Exception as e:
        print(f"[-] Error reading offline database: {e}")

def check_url_vt(target_url, api_key):
    """Queries VirusTotal for URL risk analysis."""
    if not api_key or api_key == "your_virustotal_api_key_here":
        print("[!] Error: VirusTotal API key missing.")
        return

    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"accept": "application/json", "x-apikey": api_key}

    print(f"\n[+] [VirusTotal] Analyzing URL: {target_url}...")
    try:
        response = requests.get(endpoint, headers=headers)

        if response.status_code == 404:
            print("[-] No existing threat intelligence found for this URL.")
            return

        response.raise_for_status()
        data = response.json()['data']['attributes']

        stats = data.get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)

        is_dangerous = (malicious > 0 or suspicious > 0)
        print(f"Malicious: {malicious} | Suspicious: {suspicious} | Clean: {harmless}")

        threats_str = "None"
        if is_dangerous:
            categories = data.get('categories', {})
            if categories:
                threats_str = ", ".join(list(set(categories.values())))
                print(f"Associated Threat Categories: {threats_str}")

        scan_history.append({
            "type": "URL (VirusTotal)",
            "target": target_url,
            "status": "DANGEROUS / SUSPICIOUS" if is_dangerous else "CLEAN",
            "metrics": f"Malicious Flags: {malicious}, Suspicious: {suspicious}",
            "summary": f"Categories: {threats_str}"
        })

    except requests.exceptions.RequestException as e:
        print(f"[-] Error querying VirusTotal URL API: {e}")


def check_hash_vt(file_hash, api_key):
    """Queries VirusTotal for File Hash (MD5, SHA1, SHA256) static analysis."""
    if not api_key or api_key == "your_virustotal_api_key_here":
        print("[!] Error: VirusTotal API key missing.")
        return

    endpoint = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"accept": "application/json", "x-apikey": api_key}

    print(f"\n[+] [VirusTotal] Analyzing File Hash: {file_hash}...")
    try:
        response = requests.get(endpoint, headers=headers)

        if response.status_code == 404:
            print("[-] Hash not found in VirusTotal database. This might be a novel file.")
            return

        response.raise_for_status()
        data = response.json()['data']['attributes']

        stats = data.get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)

        file_names = data.get('names', [])
        common_name = file_names[0] if file_names else "Unknown"

        is_dangerous = (malicious > 0 or suspicious > 0)
        print(f"Malicious: {malicious} | Suspicious: {suspicious}")
        print(f"Common File Name Associated: {common_name}")

        suggested_threat = data.get('popular_threat_classification', {}).get('suggested_threat_label', 'Unknown')
        if is_dangerous:
            print(f"Suggested Threat Label: {suggested_threat}")

        scan_history.append({
            "type": "File Hash (VirusTotal)",
            "target": file_hash,
            "status": "MALWARE / SUSPICIOUS" if is_dangerous else "CLEAN",
            "metrics": f"Malicious Flags: {malicious}",
            "summary": f"Label: {suggested_threat} | Known As: {common_name}"
        })

    except requests.exceptions.RequestException as e:
        print(f"[-] Error querying VirusTotal File API: {e}")


def check_tunneling_heuristics(port, protocol, service_signature=""):
    """Analyzes port and protocol to detect potential tunneling and evasion."""
    port = str(port)
    protocol = protocol.upper()
    service_signature = service_signature.upper()

    print(f"\n[+] [Evasion Check] Analyzing Port {port}/{protocol} for Tunneling Indicators...")
    warnings = []

    # 1. DNS Tunneling Heuristics
    if port == "53":
        if protocol == "TCP": warnings.append(
            "TCP on port 53. DNS normally uses UDP. High probability of zone transfer or DNS Tunneling.")
        if "SSH" in service_signature or "HTTP" in service_signature: warnings.append(
            "Non-DNS signature detected on port 53. Strong indicator of tunneling.")

    # 2. HTTP/HTTPS Evasion Heuristics (SSH/RDP over 443/80)
    elif port in ["80", "443"]:
        if "SSH" in service_signature:
            warnings.append(f"SSH signature detected on web port {port}. Strong indicator of perimeter evasion.")
        elif "RDP" in service_signature:
            warnings.append(f"RDP signature detected on web port {port}. Remote access tunneling likely.")

    # 3. ICMP Tunneling
    elif protocol == "ICMP":
        if service_signature and service_signature not in ["ECHO", "REPLY"]: warnings.append(
            "Unusual payload signature in ICMP traffic. Potential ICMP tunneling (e.g., ptunnel).")

    # 4. Common Proxy/Tunnel Default Ports
    proxy_ports = {"1080": "SOCKS Proxy (commonly used by Proxychains)", "3128": "Squid Proxy",
                   "8080": "HTTP Alternate / Proxy", "4040": "Ngrok Web Interface"}
    if port in proxy_ports: warnings.append(f"Traffic on known proxy port ({proxy_ports[port]}). Verify authorization.")

    # Result Evaluation
    if warnings:
        print("⚠️ WARNING: Suspicious tunneling characteristics detected:")
        for w in warnings: print(f"  - {w}")

        scan_history.append({
            "type": "Port/Tunnel Analysis",
            "target": f"{port}/{protocol}",
            "status": "SUSPICIOUS (TUNNELING RISK)",
            "metrics": f"{len(warnings)} Indicators Flagged",
            "summary": " | ".join(warnings)
        })
    else:
        print("✅ No immediate tunneling heuristics detected for this port/protocol combination.")
        scan_history.append({
            "type": "Port/Tunnel Analysis",
            "target": f"{port}/{protocol}",
            "status": "STANDARD TRAFFIC",
            "metrics": "0 Indicators",
            "summary": "Protocol aligns with standard port usage."
        })


# =====================================================================
# PDF REPORTING
# =====================================================================

def generate_pdf_report():
    """Generates a PDF document compilation out of the scan history list data."""
    if not scan_history:
        print("[*] No scans run during this session. Skipping PDF generation.")
        return

    filename = f"Threat_Intel_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    doc = SimpleDocTemplate(filename, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('DocTitle', parent=styles['Heading1'], fontSize=22,
                                 textColor=colors.HexColor("#1A365D"), spaceAfter=12)
    item_header_style = ParagraphStyle('ItemHeader', parent=styles['Heading2'], fontSize=12,
                                       textColor=colors.HexColor("#2C5282"), spaceBefore=10, spaceAfter=4)
    body_style = ParagraphStyle('ReportBody', parent=styles['BodyText'], fontSize=10, leading=14, spaceAfter=6)

    story = []
    story.append(Paragraph("Threat Intelligence Session Compilation Report", title_style))
    story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    story.append(Spacer(1, 15))
    story.append(Paragraph(f"Total Assets Tracked: {len(scan_history)}", styles['Heading3']))
    story.append(Spacer(1, 10))

    for idx, scan in enumerate(scan_history, 1):
        story.append(Paragraph(f"{idx}. Asset Type: {scan['type']} - {scan['target']}", item_header_style))

        status_color = "red" if "CLEAN" not in scan['status'] else "green"
        status_text = f"<b>Reputation Status:</b> <font color='{status_color}'>{scan['status']}</font>"

        story.append(Paragraph(status_text, body_style))
        story.append(Paragraph(f"<b>Metrics:</b> {scan['metrics']}", body_style))
        story.append(Paragraph(f"<b>Context Summary:</b> {scan['summary']}", body_style))
        story.append(Spacer(1, 8))

    try:
        doc.build(story)
        print(f"\n[+] Success: PDF compilation session log written cleanly to: {filename}")
    except Exception as e:
        print(f"[-] Failed to generate PDF asset log: {e}")


# =====================================================================
# CONTROL INTERFACE
# =====================================================================

def main():
    running = True
    while running:
        print("\n=========================================")
        print("     Advanced Threat Intel Toolkit      ")
        print("=========================================")
        print("1. IP Lookup ")
        print("2. Offline IP Geolocation       [Local DB]")
        print("3. URL Scanner ")
        print("4. File Hash Scanner ")
        print("5. Detect Port Tunneling ")
        print("6. Export Report & Exit")
        print("=========================================")

        choice = input("Select an option (1-5): ").strip()

        if choice == '1':
            target = input("\nEnter the IP address: ").strip()
            if target: check_ip_consensus(target, ABUSEIPDB_API_KEY, ALIENVAULT_API_KEY)
        elif choice == '2':
            target = input("\nEnter the IP address for offline geo-mapping: ").strip()
            if target: check_ip_offline_geo(target)
        elif choice == '3':
            target = input("\nEnter the URL (include http/https): ").strip()
            if target: check_url_vt(target, VIRUSTOTAL_API_KEY)

        elif choice == '4':
            target = input("\nEnter the File Hash (MD5, SHA1, or SHA256): ").strip()
            if target: check_hash_vt(target, VIRUSTOTAL_API_KEY)

        elif choice == '5':
            print("\n[+] Enter traffic details for tunneling analysis:")
            port = input("Target Port (e.g., 53, 443): ").strip()
            proto = input("Protocol (TCP, UDP, ICMP): ").strip()
            sig = input("Service Signature detected (e.g., HTTP, SSH, optional): ").strip()
            if port and proto:
                check_tunneling_heuristics(port, proto, sig)
            else:
                print("[-] Error: Port and Protocol are required fields.")

        elif choice == '6':
            print("\n[+] Finalizing background processes... Building report configuration.")
            generate_pdf_report()
            print("Exiting toolkit framework. Stay safe!")
            running = False

        else:
            print("\n[-] Invalid selection.")

        if running:
            input("\n[Press Enter to return back to Main Menu...]")


if __name__ == "__main__":
    main()