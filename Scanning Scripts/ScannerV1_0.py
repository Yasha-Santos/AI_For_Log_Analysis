import requests
import base64
from datetime import datetime

# Import ReportLab components for PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

# =====================================================================
# CONFIGURATION - INSERT API KEYS HERE
# =====================================================================
ABUSEIPDB_API_KEY = "231c4a9e71b145ec686d83d9002ed73f77d33215e81a7a859bd3076718eb6965220afc4d5195cc5b"
VIRUSTOTAL_API_KEY = "270a570af4daa177239a4b5a656d0ecd2654fc48ff3374f01d23a31db1b8b119"

# Global session cache to store scan details for the PDF summary
scan_history = []


# =====================================================================
# CORE FUNCTIONS
# =====================================================================

def check_ip(ip_address, api_key):
    """Queries AbuseIPDB for IP reputation and returns status string."""
    if api_key == "your_abuseipdb_api_key_here":
        print("[!] Error: Please configure your AbuseIPDB API key at the top of the script.")
        return "API Key Missing"

    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {'ipAddress': ip_address, 'maxAgeInDays': '90', 'verbose': True}
    headers = {'Accept': 'application/json', 'Key': api_key}

    print(f"\n[+] Scanning IP: {ip_address}...")
    try:
        response = requests.get(url, headers=headers, params=querystring)
        response.raise_for_status()
        data = response.json()['data']

        score = data['abuseConfidenceScore']
        total_reports = data['totalReports']
        is_malicious = score > 50

        print(f"\n--- Results for IP: {ip_address} ---")
        print(f"Blacklisted/Malicious: {'Yes' if is_malicious else 'No'} (Confidence Score: {score}%)")
        print(f"Total Reports in last 90 days: {total_reports}\n")

        reason_summary = ""
        if is_malicious and total_reports > 0:
            print("Reason / Summary of recent activity:")
            recent_reports = data['reports'][:3]
            for report in recent_reports:
                date = report['reportedAt'][:10]
                comment = report['comment'] if report['comment'] else "No comment provided."
                print(f"- [{date}] {comment}")
                reason_summary += f"[{date}] {comment} | "
        else:
            print("✅ This IP looks clean or has no recent malicious reports.")
            reason_summary = "Clean or no recent reports."

        # Log to structural session dictionary
        scan_history.append({
            "type": "IP Address",
            "target": ip_address,
            "status": "MALICIOUS / BLACKLISTED" if is_malicious else "CLEAN",
            "metrics": f"Confidence Score: {score}%, Total Reports: {total_reports}",
            "summary": reason_summary.strip(" | ")
        })

    except requests.exceptions.RequestException as e:
        print(f"[-] Error connecting to AbuseIPDB: {e}")


def check_url(target_url, api_key):
    """Queries VirusTotal for URL risk analysis and returns status string."""
    if api_key == "your_virustotal_api_key_here":
        print("[!] Error: Please configure your VirusTotal API key at the top of the script.")
        return

    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"accept": "application/json", "x-apikey": api_key}

    print(f"\n[+] Analyzing URL: {target_url}...")
    try:
        response = requests.get(endpoint, headers=headers)

        if response.status_code == 404:
            print(f"\n[-] No existing threat intelligence found for: {target_url}")
            return

        response.raise_for_status()
        data = response.json()['data']['attributes']

        stats = data.get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)

        print(f"\n--- Risk Report for URL: {target_url} ---")
        print(f"Malicious Flags:  {malicious}")
        print(f"Suspicious Flags: {suspicious}")
        print(f"Clean/Harmless:   {harmless}\n")

        threats_str = "None"
        if malicious > 0 or suspicious > 0:
            print("⚠️ WARNING: This URL poses a security risk.")
            categories = data.get('categories', {})
            if categories:
                unique_threats = list(set(categories.values()))
                threats_str = ", ".join(unique_threats)
                print(f"Associated Threat Categories: {threats_str}")
        else:
            print("✅ SAFE: This URL is clean according to current threat metrics.")

        scan_history.append({
            "type": "URL",
            "target": target_url,
            "status": "DANGEROUS / SUSPICIOUS" if (malicious > 0 or suspicious > 0) else "CLEAN",
            "metrics": f"Malicious Flags: {malicious}, Suspicious: {suspicious}, Harmless: {harmless}",
            "summary": f"Categories: {threats_str}"
        })

    except requests.exceptions.RequestException as e:
        print(f"[-] Error querying the VirusTotal API: {e}")


def generate_pdf_report():
    """Generates a PDF document compilation out of the scan history list data."""
    if not scan_history:
        print("[*] No scans run during this session. Skipping PDF generation.")
        return

    filename = f"Threat_Intel_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    doc = SimpleDocTemplate(filename, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)

    styles = getSampleStyleSheet()

    # Custom heading variations
    title_style = ParagraphStyle(
        'DocTitle', parent=styles['Heading1'], fontSize=22, textColor=colors.HexColor("#1A365D"), spaceAfter=12
    )
    item_header_style = ParagraphStyle(
        'ItemHeader', parent=styles['Heading2'], fontSize=12, textColor=colors.HexColor("#2C5282"), spaceBefore=10,
        spaceAfter=4
    )
    body_style = ParagraphStyle(
        'ReportBody', parent=styles['BodyText'], fontSize=10, leading=14, spaceAfter=6
    )

    story = []

    # Title Elements
    story.append(Paragraph("Threat Intelligence Session Compilation Report", title_style))
    story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    story.append(Spacer(1, 15))
    story.append(Paragraph(f"Total Assets Tracked: {len(scan_history)}", styles['Heading3']))
    story.append(Spacer(1, 10))

    # Loop history list into PDF Flowables
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
    # Use a flag variable to control the loop rather than forcing an infinite check
    running = True

    while running:
        print("\n=========================================")
        print("     Threat Intel Lookup Toolkit      ")
        print("=========================================")
        print("1. IP Reputation Lookup (AbuseIPDB)")
        print("2. URL Threat Scanner   (VirusTotal)")
        print("3. Export Report & Exit")
        print("=========================================")

        choice = input("Select an option (1-3): ").strip()

        if choice == '1':
            target_ip = input("\nEnter the IP address to check: ").strip()
            if target_ip:
                check_ip(target_ip, ABUSEIPDB_API_KEY)
            else:
                print("[-] Error: IP field cannot be blank.")

        elif choice == '2':
            target_url = input("\nEnter the URL to scan (include http/https): ").strip()
            if target_url:
                check_url(target_url, VIRUSTOTAL_API_KEY)
            else:
                print("[-] Error: URL field cannot be blank.")

        elif choice == '3':
            print("\n[+] Finalizing background processes... Building report configuration.")
            generate_pdf_report()
            print("Exiting toolkit framework. Stay safe!")
            running = False

        else:
            print("\n[-] Invalid selection. Choose options 1, 2, or 3.")

        # Only prompt for Enter if the user isn't trying to exit right now
        if running:
            input("\n[Press Enter to return back to Main Menu...]")


if __name__ == "__main__":
    main()
