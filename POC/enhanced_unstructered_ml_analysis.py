"""
AI For Log Analysis - Week 3/4 Enhanced ML Analysis

This script takes parsed log data from parsed_logs_output.json and performs:
1. Data cleanup
2. Feature extraction
3. Feature normalization
4. Anomaly detection using Isolation Forest
5. Output generation for future GUI/database use

Main outputs:
- enhanced_anomaly_results.json: detailed analyzed log records
- enhanced_log_features.csv: extracted feature table for review/testing
- feature_summary.json: summary counts useful for reports or GUI cards
"""

import json
import re
import ipaddress
from pathlib import Path

import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer


# ------------------------------------------------------------
# File configuration
# ------------------------------------------------------------
# Input file created by the parser stage.
INPUT_FILE = "parsed_logs_output.json"

# Output files created by this script.
OUTPUT_RESULTS_FILE = "enhanced_anomaly_results.json"
OUTPUT_FEATURES_FILE = "enhanced_log_features.csv"
OUTPUT_SUMMARY_FILE = "feature_summary.json"


# ------------------------------------------------------------
# Loading and basic validation
# ------------------------------------------------------------
def load_logs(file_path):
    """
    Load parsed log data from a JSON file and convert it into a pandas DataFrame.

    Expected input format:
    [
        {"timestamp": "...", "source_ip": "...", "message": "...", "raw": "..."},
        {"timestamp": "...", "source_ip": "...", "message": "...", "raw": "..."}
    ]
    """
    path = Path(file_path)

    # Stop early if the input file is missing.
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {file_path}")

    with open(path, "r", encoding="utf-8") as file:
        data = json.load(file)

    # The script expects a list of log objects, not a single dictionary.
    if not isinstance(data, list):
        raise ValueError("The input JSON should contain a list of log entries.")

    return pd.DataFrame(data)


def ensure_columns(df):
    """
    Make sure all expected columns exist before feature extraction.

    The current parser output can be inconsistent. Some records may be missing fields
    like message, destination_ip, port, or protocol. This function prevents the
    script from crashing by creating missing columns with None values.
    """
    required_columns = [
        "timestamp",
        "log_type",
        "source_ip",
        "destination_ip",
        "user",
        "message",
        "port",
        "protocol",
        "raw"
    ]

    for column in required_columns:
        if column not in df.columns:
            df[column] = None

    return df


def clean_text(value):
    """
    Standardize empty, missing, or invalid text values.

    This keeps the rest of the code simple because missing values are represented
    as the string "unknown" instead of None, NaN, or blank strings.
    """
    if pd.isna(value):
        return "unknown"

    value = str(value).strip()

    if value.lower() in ["none", "null", "", "nan"]:
        return "unknown"

    return value


# ------------------------------------------------------------
# Timestamp feature extraction
# ------------------------------------------------------------
def normalize_timestamp(value):
    """
    Convert syslog-style timestamps into pandas datetime values.

    Current logs look like:
    Dec 10 06:55:46

    Since the raw SSH logs do not include a year, a placeholder year is added so
    pandas can convert the value into a real datetime object.
    """
    value = clean_text(value)

    if value == "unknown":
        return pd.NaT

    # Fix extra spaces or broken spacing, for example "Dec 10 07:55: 55".
    value = re.sub(r"\s+", " ", value)
    value = value.replace(": ", ":")

    # Placeholder year used only so the timestamp can be parsed consistently.
    value_with_year = f"2026 {value}"

    return pd.to_datetime(value_with_year, format="%Y %b %d %H:%M:%S", errors="coerce")


def add_timestamp_features(df):
    """
    Add ML-ready time features.

    These help the model detect suspicious timing patterns, such as repeated
    activity late at night or outside normal business hours.
    """
    df["normalized_timestamp"] = df["timestamp"].apply(normalize_timestamp)

    # Extract the hour of the day from the normalized timestamp.
    df["hour"] = df["normalized_timestamp"].dt.hour.fillna(-1).astype(int)

    # Extract day of week: Monday = 0, Sunday = 6.
    df["day_of_week"] = df["normalized_timestamp"].dt.dayofweek.fillna(-1).astype(int)

    # Simple flags that may help identify unusual activity windows.
    df["is_business_hours"] = df["hour"].between(8, 18).astype(int)
    df["is_late_night"] = df["hour"].between(0, 5).astype(int)

    return df


# ------------------------------------------------------------
# IP address feature extraction
# ------------------------------------------------------------
def extract_valid_ips(text):
    """
    Extract valid IPv4 addresses from a text value.

    Some parsed source_ip fields are broken, incomplete, or contain extra text.
    This function validates IPs using Python's ipaddress module and ignores bad IPs.
    """
    if pd.isna(text):
        return []

    # Find IP-looking patterns first.
    possible_ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", str(text))
    valid_ips = []

    # Keep only valid IPv4 addresses.
    for ip in possible_ips:
        try:
            valid_ips.append(str(ipaddress.ip_address(ip)))
        except ValueError:
            continue

    return valid_ips


def get_best_source_ip(row):
    """
    Choose the best available source IP for a log record.

    Priority:
    1. Use source_ip if it contains a valid IP.
    2. If source_ip is missing/bad, extract IP from the raw log line.
    3. If raw does not work, try the message field.
    4. If nothing is valid, return "unknown".
    """
    source_ips = extract_valid_ips(row.get("source_ip"))

    if source_ips:
        return source_ips[0]

    raw_ips = extract_valid_ips(row.get("raw"))

    if raw_ips:
        return raw_ips[0]

    message_ips = extract_valid_ips(row.get("message"))

    if message_ips:
        return message_ips[0]

    return "unknown"


def get_destination_ip(row):
    """
    Extract destination IP if available.

    Current SSH auth logs usually do not include a destination IP, so this will
    often return "unknown". This field is still included because future firewall,
    web, or network logs may contain destination IPs.
    """
    destination_ips = extract_valid_ips(row.get("destination_ip"))

    if destination_ips:
        return destination_ips[0]

    return "unknown"


def ip_to_int(value):
    """
    Convert an IP address into a numeric value.

    Machine learning models cannot directly understand IP address strings, so this
    creates a numeric representation. Invalid IPs become -1.
    """
    try:
        return int(ipaddress.ip_address(value))
    except ValueError:
        return -1


def is_private_ip(value):
    """
    Identify whether an IP address is private/internal.

    Example private ranges:
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
    """
    try:
        return int(ipaddress.ip_address(value).is_private)
    except ValueError:
        return 0


def get_ip_network(value):
    """
    Group IPv4 addresses into a simple /24-style network.

    Example:
    112.95.230.3 -> 112.95.230.0/24

    This helps the model identify repeated activity from the same network range.
    """
    try:
        ip = ipaddress.ip_address(value)

        if ip.version == 4:
            parts = value.split(".")
            return ".".join(parts[:3]) + ".0/24"

        return "ipv6"

    except ValueError:
        return "unknown"


def add_ip_features(df):
    """
    Add cleaned IP and network-related features.

    These features improve the old approach that only used the first IP octet.
    """
    # Clean/repair source and destination IPs.
    df["source_ip_clean"] = df.apply(get_best_source_ip, axis=1)
    df["destination_ip_clean"] = df.apply(get_destination_ip, axis=1)

    # Numeric IP versions for machine learning.
    df["source_ip_numeric"] = df["source_ip_clean"].apply(ip_to_int)
    df["destination_ip_numeric"] = df["destination_ip_clean"].apply(ip_to_int)

    # Flags showing whether IPs are private/internal.
    df["source_is_private"] = df["source_ip_clean"].apply(is_private_ip)
    df["destination_is_private"] = df["destination_ip_clean"].apply(is_private_ip)

    # Network grouping features.
    df["source_network"] = df["source_ip_clean"].apply(get_ip_network)
    df["destination_network"] = df["destination_ip_clean"].apply(get_ip_network)

    # Shows whether a usable source IP was found.
    df["has_valid_source_ip"] = (df["source_ip_clean"] != "unknown").astype(int)

    return df


# ------------------------------------------------------------
# Port and protocol feature extraction
# ------------------------------------------------------------
def extract_port(text):
    """
    Extract a port number from a log line.

    Example:
    "Failed password for root from 1.2.3.4 port 42393 ssh2"
    returns 42393.
    """
    if pd.isna(text):
        return -1

    match = re.search(r"\bport\s+(\d{1,5})\b", str(text).lower())

    if not match:
        return -1

    port = int(match.group(1))

    # Valid TCP/UDP ports are between 0 and 65535.
    if 0 <= port <= 65535:
        return port

    return -1


def extract_protocol(text):
    """
    Extract a simple protocol label from the raw log text.

    Current POC data is mostly SSH/SSH2, but HTTP/HTTPS are included for future use.
    """
    if pd.isna(text):
        return "unknown"

    text = str(text).lower()

    if "ssh2" in text:
        return "ssh2"

    if "sshd" in text or "ssh" in text:
        return "ssh"

    if "https" in text:
        return "https"

    if "http" in text:
        return "http"

    return "unknown"


def add_port_protocol_features(df):
    """
    Add cleaned port and protocol features.

    The script first checks the raw log line because it usually contains the most
    complete information. If no port is found in raw, it tries the message field.
    """
    df["port_clean"] = df["raw"].apply(extract_port)

    # Try message field only where raw did not contain a port.
    missing_port = df["port_clean"] == -1
    df.loc[missing_port, "port_clean"] = df.loc[missing_port, "message"].apply(extract_port)

    df["protocol_clean"] = df["raw"].apply(extract_protocol)

    # Flag common administrative or service ports.
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389]
    df["is_common_port"] = df["port_clean"].isin(common_ports).astype(int)

    return df


# ------------------------------------------------------------
# User/account feature extraction
# ------------------------------------------------------------
def extract_user_from_raw(raw):
    """
    Extract usernames from common SSH log patterns.

    Examples:
    - Invalid user admin from 1.2.3.4
    - Failed password for root from 1.2.3.4
    - user=root
    """
    raw = clean_text(raw)

    if raw == "unknown":
        return "unknown"

    raw_lower = raw.lower()

    patterns = [
        r"invalid user\s+([a-zA-Z0-9._-]+)",
        r"failed password for invalid user\s+([a-zA-Z0-9._-]+)",
        r"failed password for\s+([a-zA-Z0-9._-]+)",
        r"user=([a-zA-Z0-9._-]+)"
    ]

    for pattern in patterns:
        match = re.search(pattern, raw_lower)
        if match:
            return match.group(1)

    return "unknown"


def normalize_user(row):
    """
    Clean the user field and repair it from raw logs when needed.

    Some parsed user values contain extra text like [preauth] or full messages.
    If the parsed user value looks bad, the script extracts the username from raw.
    """
    current_user = clean_text(row.get("user")).lower()

    bad_values = [
        "unknown",
        "none",
        "id string",
        "request was closed due to user request. [preauth]"
    ]

    # Use the current user value only if it looks clean.
    if (
        current_user not in bad_values
        and "invalid user" not in current_user
        and "[preauth]" not in current_user
    ):
        return current_user

    # Otherwise, try to repair the username from the raw log.
    return extract_user_from_raw(row.get("raw"))


def add_user_features(df):
    """
    Add account-related features.

    Root/admin activity can be important in security logs, so it gets a dedicated flag.
    """
    df["user_clean"] = df.apply(normalize_user, axis=1)

    df["is_root_user"] = (df["user_clean"] == "root").astype(int)
    df["is_unknown_user"] = (df["user_clean"] == "unknown").astype(int)

    return df


# ------------------------------------------------------------
# Message/event feature extraction
# ------------------------------------------------------------
def get_best_message(row):
    """
    Choose the best message text for each log record.

    If the parsed message exists, use it. If it is missing, extract the event
    portion from the raw SSH log line.
    """
    message = clean_text(row.get("message"))

    if message != "unknown":
        return message

    raw = clean_text(row.get("raw"))

    if raw == "unknown":
        return "unknown"

    # Remove syslog prefix and keep only the event part after sshd[pid]:
    if "sshd" in raw:
        parts = raw.split(  # Split only once, after the process marker.
            "]:",
            1
        )
        if len(parts) == 2:
            return parts[1].strip()

    return raw


def normalize_message_type(message):
    """
    Convert raw message text into a normalized event category.

    This makes logs easier to summarize, visualize, and use in ML models.
    """
    message = clean_text(message).lower()

    if "possible break-in attempt" in message or "break-in" in message:
        return "possible_break_in"

    if "too many authentication failures" in message or "max retries" in message:
        return "too_many_failures"

    if "failed password" in message or "authentication failure" in message or "auth fail" in message:
        return "auth_failure"

    if "invalid user" in message or "user unknown" in message:
        return "invalid_user"

    if "accepted password" in message or "accepted publickey" in message or "success" in message:
        return "auth_success"

    if "connection closed" in message or "disconnect" in message or "received disconnect" in message:
        return "connection_closed"

    if "did not receive identification string" in message:
        return "no_identification_string"

    if "root" in message or "sudo" in message or "administrator" in message:
        return "privilege_related"

    return "other"


def extract_domains(text):
    """
    Extract domain names from raw log text.

    This supports future enrichment work, such as domain reputation checks.
    """
    if pd.isna(text):
        return []

    pattern = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
    return re.findall(pattern, str(text))


def extract_urls(text):
    """
    Extract URLs from raw log text.

    Current SSH logs may not have many URLs, but this is useful for future web logs.
    """
    if pd.isna(text):
        return []

    pattern = r"https?://[^\s]+"
    return re.findall(pattern, str(text))


def add_message_features(df):
    """
    Add event/message-related features.

    This includes:
    - cleaned message text
    - normalized event category
    - domain and URL counts
    - keyword flags such as failed, invalid, root, break-in, and disconnect
    """
    df["message_clean"] = df.apply(get_best_message, axis=1)

    # Use both cleaned message and raw log for classification.
    # This fixes cases where the parsed message is incomplete but raw has the full event.
    df["classification_text"] = (
        df["message_clean"].fillna("").astype(str)
        + " "
        + df["raw"].fillna("").astype(str)
    )

    df["normalized_message"] = df["classification_text"].apply(normalize_message_type)

    # Extract indicators that could later be used for enrichment or reputation checks.
    df["domains"] = df["raw"].apply(extract_domains)
    df["urls"] = df["raw"].apply(extract_urls)

    df["domain_count"] = df["domains"].apply(len)
    df["url_count"] = df["urls"].apply(len)

    # Basic text-size features.
    df["message_length"] = df["message_clean"].str.len()
    df["word_count"] = df["message_clean"].str.split().apply(len)

    # Keyword flags used as ML features.
    lower_message = df["classification_text"].str.lower()

    df["contains_failed"] = lower_message.str.contains("failed|failure", na=False).astype(int)
    df["contains_invalid"] = lower_message.str.contains("invalid", na=False).astype(int)
    df["contains_root"] = lower_message.str.contains("root", na=False).astype(int)
    df["contains_breakin"] = lower_message.str.contains("break-in|possible break", na=False).astype(int)
    df["contains_disconnect"] = lower_message.str.contains("disconnect|closed", na=False).astype(int)

    return df


# ------------------------------------------------------------
# Behaviour/frequency feature extraction
# ------------------------------------------------------------
def add_behavior_features(df):
    """
    Add frequency-based behaviour features.

    These are useful for detecting brute-force style behaviour, such as many failed
    attempts from the same IP or repeated attempts against the same username.
    """
    # Total number of events from each source IP.
    df["events_from_same_ip"] = df.groupby("source_ip_clean")["source_ip_clean"].transform("count")

    # Total number of events for each username.
    df["events_for_same_user"] = df.groupby("user_clean")["user_clean"].transform("count")

    # Number of events for the same source IP and same username pair.
    df["same_ip_user_attempts"] = df.groupby(["source_ip_clean", "user_clean"])["user_clean"].transform("count")

    # Number of failed events from the same source IP.
    df["failed_events_from_same_ip"] = df.groupby("source_ip_clean")["contains_failed"].transform("sum")

    return df


# ------------------------------------------------------------
# Feature-building pipeline
# ------------------------------------------------------------
def build_features(df):
    """
    Run all feature extraction steps in the correct order.
    """
    df = ensure_columns(df)

    # Basic cleanup before deeper feature extraction.
    df["log_type"] = df["log_type"].apply(clean_text).str.lower()
    df["raw"] = df["raw"].apply(clean_text)

    # Add feature groups.
    df = add_timestamp_features(df)
    df = add_ip_features(df)
    df = add_port_protocol_features(df)
    df = add_user_features(df)
    df = add_message_features(df)
    df = add_behavior_features(df)

    return df


# ------------------------------------------------------------
# Machine learning anomaly detection
# ------------------------------------------------------------
def run_anomaly_detection(df):
    """
    Run Isolation Forest anomaly detection.

    The model uses:
    - categorical features encoded with OneHotEncoder
    - numeric features scaled with StandardScaler
    - message text converted with TF-IDF

    Isolation Forest is used because the POC does not have clean labels for every
    normal and malicious event.
    """
    categorical_features = [
        "log_type",
        "user_clean",
        "normalized_message",
        "source_network",
        "destination_network",
        "protocol_clean"
    ]

    numeric_features = [
        "hour",
        "day_of_week",
        "is_business_hours",
        "is_late_night",
        "source_ip_numeric",
        "destination_ip_numeric",
        "source_is_private",
        "destination_is_private",
        "has_valid_source_ip",
        "port_clean",
        "is_common_port",
        "domain_count",
        "url_count",
        "message_length",
        "word_count",
        "contains_failed",
        "contains_invalid",
        "contains_root",
        "contains_breakin",
        "contains_disconnect",
        "is_root_user",
        "is_unknown_user",
        "events_from_same_ip",
        "events_for_same_user",
        "same_ip_user_attempts",
        "failed_events_from_same_ip"
    ]

    text_feature = "message_clean"

    # ColumnTransformer applies different preprocessing to different feature types.
    preprocessor = ColumnTransformer(
        transformers=[
            ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_features),
            ("num", StandardScaler(), numeric_features),
            ("msg", TfidfVectorizer(max_features=100, stop_words="english"), text_feature)
        ]
    )

    # contamination=0.05 means the model expects about 5% of records to be anomalies.
    model = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        random_state=42
    )

    # Pipeline keeps preprocessing and model training together.
    pipeline = Pipeline([
        ("preprocessing", preprocessor),
        ("model", model)
    ])

    pipeline.fit(df)

    # decision_function gives anomaly scores. Lower scores are more suspicious.
    df["anomaly_score"] = pipeline.decision_function(df)

    # predict returns 1 for normal and -1 for anomaly.
    df["anomaly"] = pipeline.predict(df)

    # Convert numeric model output into readable labels.
    df["anomaly_label"] = df["anomaly"].map({
        1: "normal",
        -1: "anomaly"
    })

    return df


# ------------------------------------------------------------
# Output generation
# ------------------------------------------------------------
def save_outputs(df):
    """
    Save three output files:

    1. enhanced_anomaly_results.json
       Detailed analyzed records for the future GUI/database.

    2. enhanced_log_features.csv
       Feature table that can be reviewed, tested, or shown as evidence.

    3. feature_summary.json
       Summary counts useful for reports and dashboard cards.
    """
    results_columns = [
        "timestamp",
        "normalized_timestamp",
        "log_type",
        "source_ip",
        "source_ip_clean",
        "destination_ip_clean",
        "source_network",
        "user",
        "user_clean",
        "port_clean",
        "protocol_clean",
        "normalized_message",
        "message_clean",
        "domains",
        "urls",
        "events_from_same_ip",
        "failed_events_from_same_ip",
        "same_ip_user_attempts",
        "anomaly_label",
        "anomaly_score",
        "raw"
    ]

    # Only save columns that exist in the current DataFrame.
    existing_results_columns = [col for col in results_columns if col in df.columns]

    results_df = df[existing_results_columns].copy()

    # Convert datetime to string so JSON export works cleanly.
    results_df["normalized_timestamp"] = results_df["normalized_timestamp"].astype(str)

    results_df.to_json(OUTPUT_RESULTS_FILE, orient="records", indent=4)

    feature_columns = [
        "hour",
        "day_of_week",
        "is_business_hours",
        "is_late_night",
        "source_ip_clean",
        "source_network",
        "source_is_private",
        "has_valid_source_ip",
        "user_clean",
        "is_root_user",
        "is_unknown_user",
        "port_clean",
        "protocol_clean",
        "normalized_message",
        "domain_count",
        "url_count",
        "message_length",
        "word_count",
        "contains_failed",
        "contains_invalid",
        "contains_root",
        "contains_breakin",
        "contains_disconnect",
        "events_from_same_ip",
        "events_for_same_user",
        "same_ip_user_attempts",
        "failed_events_from_same_ip",
        "anomaly_label",
        "anomaly_score"
    ]

    existing_feature_columns = [col for col in feature_columns if col in df.columns]
    df[existing_feature_columns].to_csv(OUTPUT_FEATURES_FILE, index=False)

    # Build a compact summary that can be used in weekly reports or a dashboard.
    summary = {
        "total_logs": int(len(df)),
        "normal_logs": int((df["anomaly_label"] == "normal").sum()),
        "anomalies_detected": int((df["anomaly_label"] == "anomaly").sum()),
        "unique_source_ips": int(df["source_ip_clean"].nunique()),
        "valid_source_ip_logs": int(df["has_valid_source_ip"].sum()),
        "auth_failures": int((df["normalized_message"] == "auth_failure").sum()),
        "invalid_user_events": int((df["normalized_message"] == "invalid_user").sum()),
        "possible_break_in_events": int((df["normalized_message"] == "possible_break_in").sum()),
        "root_user_events": int(df["is_root_user"].sum()),
        "top_source_ips": df["source_ip_clean"].value_counts().head(10).to_dict(),
        "top_event_types": df["normalized_message"].value_counts().to_dict()
    }

    with open(OUTPUT_SUMMARY_FILE, "w", encoding="utf-8") as file:
        json.dump(summary, file, indent=4)

    print(f"\nSaved: {OUTPUT_RESULTS_FILE}")
    print(f"Saved: {OUTPUT_FEATURES_FILE}")
    print(f"Saved: {OUTPUT_SUMMARY_FILE}")


def print_summary(df):
    """
    Print a readable terminal summary after the script runs.
    """
    print("\n========================================")
    print(" Week 3-4 Feature Extraction Summary")
    print("========================================")

    print(f"Total logs analyzed: {len(df)}")
    print(f"Normal logs: {(df['anomaly_label'] == 'normal').sum()}")
    print(f"Anomalies detected: {(df['anomaly_label'] == 'anomaly').sum()}")
    print(f"Unique source IPs: {df['source_ip_clean'].nunique()}")
    print(f"Valid source IP logs: {df['has_valid_source_ip'].sum()}")

    print("\nTop event categories:")
    print(df["normalized_message"].value_counts().head(10))

    print("\nTop source IPs:")
    print(df["source_ip_clean"].value_counts().head(10))

    print("\nSample anomalies:")
    anomalies = df[df["anomaly_label"] == "anomaly"].sort_values("anomaly_score")

    if anomalies.empty:
        print("No anomalies detected.")
        return

    # Only show the first 10 anomalies to keep terminal output readable.
    for _, row in anomalies.head(10).iterrows():
        print("\nAnomalous log:")
        print(f"  Time: {row.get('timestamp', 'N/A')}")
        print(f"  Source IP: {row.get('source_ip_clean', 'N/A')}")
        print(f"  User: {row.get('user_clean', 'N/A')}")
        print(f"  Port: {row.get('port_clean', 'N/A')}")
        print(f"  Protocol: {row.get('protocol_clean', 'N/A')}")
        print(f"  Event Type: {row.get('normalized_message', 'N/A')}")
        print(f"  Events From Same IP: {row.get('events_from_same_ip', 'N/A')}")
        print(f"  Failed Events From Same IP: {row.get('failed_events_from_same_ip', 'N/A')}")
        print(f"  Score: {row.get('anomaly_score', 0):.4f}")
        print(f"  Message: {row.get('message_clean', 'N/A')}")
        print("-" * 70)


# ------------------------------------------------------------
# Main program entry point
# ------------------------------------------------------------
def main():
    """
    Main workflow:
    1. Load parsed logs
    2. Build enhanced features
    3. Run anomaly detection
    4. Print summary
    5. Save output files
    """
    df = load_logs(INPUT_FILE)
    df = build_features(df)
    df = run_anomaly_detection(df)

    print_summary(df)
    save_outputs(df)


if __name__ == "__main__":
    main()
