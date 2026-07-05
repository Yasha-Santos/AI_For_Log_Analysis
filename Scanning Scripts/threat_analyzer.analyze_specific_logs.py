import os
import csv
import requests
from datetime import datetime

# PDF generation engine components
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

# =====================================================================
# CONFIGURATION - INSERT YOUR API KEYS HERE
# =====================================================================
ABUSEIPDB_API_KEY = "231c4a9e71b145ec686d83d9002ed73f77d33215e81a7a859bd3076718eb6965220afc4d5195cc5b"
ALIENVAULT_API_KEY = 'cf208987d93d8363ba2164f21d6f5c4908c48d265e662a7bec2ed7460680da1c'
GEO_DB_PATH = "GeoLite2-Country.mmdb"


def _evaluate_threat(row_num, src_ip, dst_ip, message, csv_score, csv_flag):
    """
    Internal helper function to prevent code duplication.
    Runs the geolocation, API calls, and risk scoring for a single extracted row.
    """
    calculated_risk = 0.0
    if csv_flag == 1:
        calculated_risk += 40.0
    if csv_score < -0.4:
        calculated_risk += min(40.0, abs(csv_score + 0.4) * 200)

    country_name = "Unknown Country"
    iso_code = "??"
    intel_alerts = []

    # Step 1: Run Air-Gapped Country Geolocation Lookup
    if src_ip and os.path.exists(GEO_DB_PATH):
        try:
            import geoip2.database
            with geoip2.database.Reader(GEO_DB_PATH) as reader:
                geo_data = reader.country(src_ip)
                country_name = geo_data.country.name or "Unknown Country"
                iso_code = geo_data.country.iso_code or "??"
        except Exception:
            pass

    # Step 2: Check External Threat Feeds (Skip internal subnets)
    is_internal = src_ip.startswith("192.168.") or src_ip.startswith("10.") or src_ip.startswith(
        "172.16.") or src_ip == "127.0.0.1"

    if src_ip and not is_internal:
        # Check AbuseIPDB API
        if ABUSEIPDB_API_KEY and ABUSEIPDB_API_KEY != "your_abuseipdb_api_key_here":
            try:
                url = 'https://api.abuseipdb.com/api/v2/check'
                headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}
                r = requests.get(url, headers=headers, params={'ipAddress': src_ip, 'maxAgeInDays': '90'},
                                 timeout=5)
                if r.status_code == 200:
                    abuse_conf = r.json()['data']['abuseConfidenceScore']
                    calculated_risk += (abuse_conf * 0.4)
                    intel_alerts.append(f"AbuseIPDB Score: {abuse_conf}%")
            except Exception:
                pass

        # Check AlienVault OTX API
        if ALIENVAULT_API_KEY and ALIENVAULT_API_KEY != "your_alienvault_otx_api_key_here":
            try:
                url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{src_ip}/general"
                headers = {'X-OTX-API-KEY': ALIENVAULT_API_KEY}
                r = requests.get(url, headers=headers, timeout=5)
                if r.status_code == 200:
                    pulses_count = r.json().get('pulse_info', {}).get('count', 0)
                    calculated_risk += min(20.0, pulses_count * 4)
                    intel_alerts.append(f"AlienVault Pulses: {pulses_count}")
            except Exception:
                pass
    else:
        intel_alerts.append("Internal LAN Address (Skipped Cloud APIs)")

    # Normalize final structural threat visibility score
    final_threat_index = min(100.0, calculated_risk)

    # Categorize Severity Rating
    if final_threat_index >= 75:
        severity = "CRITICAL"
    elif final_threat_index >= 45:
        severity = "HIGH"
    elif final_threat_index >= 20:
        severity = "SUSPICIOUS"
    else:
        severity = "INFORMATIONAL"

    intel_summary_str = " | ".join(intel_alerts) if intel_alerts else "No active external metrics matching"

    return {
        "row_id": row_num,
        "risk_score": final_threat_index,
        "severity": severity,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "country": f"{country_name} ({iso_code})",
        "payload": message,
        "csv_score": csv_score,
        "intel_summary": intel_summary_str
    }


def process_log_dataset(file_path):
    """Parses the entire CSV row-by-row, filters out non-anomalies (0), and analyzes the rest."""
    print(f"[+] Ingesting: {file_path}")
    processed_incidents = []

    try:
        import pandas as pd
        df = pd.read_csv(file_path)
        df['_row_identifier'] = df.index + 2
        rows_iterable = df.to_dict(orient='records')
    except ImportError:
        rows_iterable = []
        with open(file_path, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for idx, row in enumerate(reader):
                row['_row_identifier'] = idx + 2
                rows_iterable.append(row)

    total_records = len(rows_iterable)
    print(f"[+] Successfully loaded {total_records} rows from CSV file.")
    print(f"\n[+] Triage underway. Analyzing anomalous entries line-by-line...\n")

    for row in rows_iterable:
        row_num = row['_row_identifier']
        src_ip = str(row.get('src_ip', '')).strip()
        dst_ip = str(row.get('dst_ip', '')).strip()
        message = row.get('message', 'N/A')

        try:
            csv_score = float(row.get('anomaly_score', 0))
            csv_flag = int(row.get('is_anomaly', 0))
        except (ValueError, TypeError):
            csv_score = 0.0
            csv_flag = 0

        # Skip the row entirely if it is not flagged as an anomaly
        if csv_flag == 0:
            continue

        print(f" -> Analyzing Row #{row_num} (Anomaly Detected) | Src: {src_ip}")
        incident_data = _evaluate_threat(row_num, src_ip, dst_ip, message, csv_score, csv_flag)
        processed_incidents.append(incident_data)

    return processed_incidents


def process_specific_rows(file_path, target_rows):
    """
    Parses the CSV but ONLY analyzes the specific row numbers provided in the target_rows list.
    Analyzes them regardless of whether the anomaly score is 0 or 1.
    Note: Data usually starts at Row 2 (because Row 1 is the header).
    """
    print(f"[+] Ingesting: {file_path} (Targeted Rows: {target_rows})")
    processed_incidents = []

    try:
        import pandas as pd
        df = pd.read_csv(file_path)
        df['_row_identifier'] = df.index + 2
        rows_iterable = df.to_dict(orient='records')
    except ImportError:
        rows_iterable = []
        with open(file_path, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for idx, row in enumerate(reader):
                row['_row_identifier'] = idx + 2
                rows_iterable.append(row)

    print(f"\n[+] Triage underway. Analyzing strictly the targeted rows...\n")

    for row in rows_iterable:
        row_num = row['_row_identifier']

        # SKIP if the row number is not in our targeted list
        if row_num not in target_rows:
            continue

        src_ip = str(row.get('src_ip', '')).strip()
        dst_ip = str(row.get('dst_ip', '')).strip()
        message = row.get('message', 'N/A')

        try:
            csv_score = float(row.get('anomaly_score', 0))
            csv_flag = int(row.get('is_anomaly', 0))
        except (ValueError, TypeError):
            csv_score = 0.0
            csv_flag = 0

        # NOTE: We DO NOT check 'if csv_flag == 0' here. We analyze it regardless.
        print(f" -> Analyzing Targeted Row #{row_num} | Src: {src_ip} | Score: {csv_score}")

        incident_data = _evaluate_threat(row_num, src_ip, dst_ip, message, csv_score, csv_flag)
        processed_incidents.append(incident_data)

    return processed_incidents


def generate_prioritized_pdf(processed_incidents):
    """Sorts all analyzed row items by risk rank and builds a clean ReportLab PDF document."""
    if not processed_incidents:
        print("[-] Data list is empty. PDF generation skipped.")
        return None

    # CRITICAL SORT: Highest computed risk scores go straight to index position 0 (the top)
    sorted_incidents = sorted(processed_incidents, key=lambda x: x['risk_score'], reverse=True)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    pdf_filename = f"Prioritized_Threat_Report_{timestamp}.pdf"

    doc = SimpleDocTemplate(pdf_filename, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()

    # Custom typography style structures
    title_style = ParagraphStyle('DocTitle', parent=styles['Heading1'], fontSize=20,
                                 textColor=colors.HexColor("#1A365D"), spaceAfter=15)
    row_header_style = ParagraphStyle('RowHeader', parent=styles['Heading2'], fontSize=11,
                                      textColor=colors.HexColor("#2C5282"), spaceBefore=12, spaceAfter=4)
    body_style = ParagraphStyle('ReportBody', parent=styles['BodyText'], fontSize=9, leading=13, spaceAfter=3)

    story = [
        Paragraph("Prioritized SOC Automated Log Analysis Brief", title_style),
        Paragraph(f"Analysis Timeline: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']),
        Spacer(1, 15),
        Paragraph(f"Total Triage Count: {len(sorted_incidents)} items evaluated and reordered by risk factor.",
                  styles['Italic']),
        Spacer(1, 10)
    ]

    for rank, incident in enumerate(sorted_incidents, 1):
        header_text = f"Rank #{rank} — [Row #{incident['row_id']}] Threat Target: {incident['src_ip']} ➔ {incident['dst_ip']}"
        story.append(Paragraph(header_text, row_header_style))

        sev = incident['severity']
        sev_color = "red" if sev in ["CRITICAL", "HIGH"] else ("orange" if sev == "SUSPICIOUS" else "green")

        story.append(Paragraph(
            f"<b>Risk Score:</b> {incident['risk_score']:.1f}/100 | <b>Severity Category:</b> <font color='{sev_color}'><b>{sev}</b></font>",
            body_style))
        story.append(Paragraph(f"<b>Geographical Boundary:</b> {incident['country']}", body_style))
        story.append(Paragraph(f"<b>Payload / Directory Checked:</b> <code>{incident['payload']}</code>", body_style))
        story.append(Paragraph(f"<b>Log Framework Model Metric:</b> {incident['csv_score']}", body_style))
        story.append(Paragraph(f"<b>Threat Intel Context:</b> {incident['intel_summary']}", body_style))
        story.append(Spacer(1, 4))

    try:
        doc.build(story)
        print(f"\n[+] Processing Complete: Sorted threat brief saved directly to: {pdf_filename}")
        return pdf_filename
    except Exception as e:
        print(f"[-] Compilation error generating PDF report: {e}")
        return None


def analyze_logs(csv_file):
    """
    Analyzes the entire CSV file but skips rows where is_anomaly == 0.
    """
    print("=====================================================")
    print("      Automated CSV Threat Ingestion Engine          ")
    print("=====================================================")

    if not os.path.exists(csv_file) or not csv_file.lower().endswith('.csv'):
        print(f"[-] Selected file format or path is invalid: {csv_file}")
        return None

    incidents_data = process_log_dataset(csv_file)
    print("\n[+] Reordering assets. Building prioritized PDF data arrays...")
    generated_pdf_path = generate_prioritized_pdf(incidents_data)
    return generated_pdf_path


def analyze_specific_logs(csv_file, target_rows):
    """
    Analyzes strictly the target rows provided in a list (e.g., [10, 5, 20]).
    Does NOT skip rows if is_anomaly == 0.
    """
    print("=====================================================")
    print("   Targeted CSV Threat Ingestion Engine (Bypass)     ")
    print("=====================================================")

    if not os.path.exists(csv_file) or not csv_file.lower().endswith('.csv'):
        print(f"[-] Selected file format or path is invalid: {csv_file}")
        return None

    if not isinstance(target_rows, list) or len(target_rows) == 0:
        print("[-] You must provide a valid list of row numbers to analyze (e.g., [2, 5, 10]).")
        return None

    incidents_data = process_specific_rows(csv_file, target_rows)
    print("\n[+] Reordering assets. Building prioritized PDF data arrays...")
    generated_pdf_path = generate_prioritized_pdf(incidents_data)
    return generated_pdf_path


if __name__ == "__main__":
    # Example 1: Run the normal analysis (skips rows where is_anomaly is 0)
    # analyze_logs("your_sample_data.csv")

    # Example 2: Force analyze specific rows regardless of anomaly status
    # analyze_specific_logs("your_sample_data.csv", [2, 15, 22])
    pass