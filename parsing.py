import pandas as pd
import utils as utils


###############################################################################
# CONFIG
###############################################################################

LOGFILE = r"D:\vscode\capstone\part2\cybersecurity_threat_detection_logs.csv"

COMMON_ALIASES = {
    "time": [
        "timestamp",
        "ts",
        "datetime"
    ],

    "src_ip": [
        "src",
        "source",
        "source_ip"
    ],

    "dst_ip": [
        "dst",
        "destination",
        "destination_ip",
        "dest_ip"
    ],

    "message": [
        "msg",
        "event",
        "log",
        "message",
        "request_path"
    ]
}


###############################################################################
# LOAD RAW LOG FILE
###############################################################################

df = pd.read_csv(LOGFILE)

# normalize column names
df.columns = [
    col.strip().lower()
    for col in df.columns
]


###############################################################################
# DETECT COLUMN MAPPINGS
###############################################################################

def detect_column_mapping(df_columns, alias_dict):

    mapping = {}

    for standard_name, aliases in alias_dict.items():

        detected_col = None

        for col in df_columns:

            # exact match
            if col == standard_name:
                detected_col = col
                break

            # alias match
            if col in aliases:
                detected_col = col
                break

        mapping[standard_name] = detected_col

    return mapping


mapping = detect_column_mapping(
    df.columns,
    COMMON_ALIASES
)


###############################################################################
# BUILD NORMALIZED DATAFRAME
###############################################################################

def build_normalized_dataframe(df, mapping):

    normalized_df = pd.DataFrame()

    for standard_name, original_col in mapping.items():

        if original_col is not None:
            normalized_df[standard_name] = df[original_col]

        else:
            normalized_df[standard_name] = None

    return normalized_df


normalized_df = build_normalized_dataframe(
    df,
    mapping
)


###############################################################################
# SHOW DETECTED MAPPINGS
###############################################################################

print("=" * 80)
print("DETECTED COLUMN MAPPING")
print("=" * 80)

for standard_name, detected_col in mapping.items():
    print(f"{standard_name:<10} --> {detected_col}")

print("\n")


###############################################################################
# FEATURE ENGINEERING
###############################################################################

print("=" * 80)
print("ADDING FEATURES")
print("=" * 80)


# ---------------------------------------------------------------------------
# unix timestamp
# ---------------------------------------------------------------------------

normalized_df = utils.add_unix_timestamp_column(
    normalized_df
)


# ---------------------------------------------------------------------------
# encode source IP
# ---------------------------------------------------------------------------

normalized_df = utils.encode_ip_column(
    normalized_df,
    column_name="src_ip",
    new_column="src_ip_encoded"
)


# ---------------------------------------------------------------------------
# encode destination IP
# ---------------------------------------------------------------------------

normalized_df = utils.encode_ip_column(
    normalized_df,
    column_name="dst_ip",
    new_column="dst_ip_encoded"
)


# ---------------------------------------------------------------------------
# semantic message encoding
# ---------------------------------------------------------------------------

normalized_df, vectorizer, svd = (
    utils.encode_message_semantics(
        normalized_df
    )
)


# ---------------------------------------------------------------------------
# logs in previous 30 minutes
# ---------------------------------------------------------------------------

normalized_df = (
    utils.add_logs_last_time_window_feature(
        normalized_df,
        minutes=30
    )
)


# ---------------------------------------------------------------------------
# logs in previous 5 minutes
# ---------------------------------------------------------------------------

normalized_df = (
    utils.add_logs_last_time_window_feature(
        normalized_df,
        minutes=5
    )
)


# ---------------------------------------------------------------------------
# time required for previous 200 logs
# ---------------------------------------------------------------------------

normalized_df = (
    utils.add_time_for_previous_n_logs(
        normalized_df,
        n=16000,
        new_col="time_for_previous_16000_logs"
    )
)


# ---------------------------------------------------------------------------
# time required for previous 50 logs
# ---------------------------------------------------------------------------

normalized_df = (
    utils.add_time_for_previous_n_logs(
        normalized_df,
        n=50,
        new_col="time_for_previous_50_logs"
    )
)


###############################################################################
# FINAL OUTPUT
###############################################################################

pd.set_option("display.max_columns", None)

print("\n")
print("=" * 80)
print("FINAL NORMALIZED DATAFRAME")
print("=" * 80)

print(normalized_df.tail(60))

###############################################################################
# ADVANCED CYBERSECURITY FEATURES
###############################################################################

# source ip logs in previous 5 minutes
normalized_df = (
    utils.add_src_ip_logs_last_time_window_feature(
        normalized_df,
        minutes=5
    )
)

# source ip logs in previous 30 minutes
normalized_df = (
    utils.add_src_ip_logs_last_time_window_feature(
        normalized_df,
        minutes=30
    )
)

# unique destination ips contacted recently
normalized_df = (
    utils.add_unique_dst_ips_last_time_window(
        normalized_df,
        minutes=5
    )
)

# time since previous event from same source ip
normalized_df = (
    utils.add_time_since_last_src_ip_event(
        normalized_df
    )
)

# message frequency
normalized_df = (
    utils.add_message_frequency_feature(
        normalized_df
    )
)

# source ip frequency
normalized_df = (
    utils.add_src_ip_frequency_feature(
        normalized_df
    )
)

# first time source ip seen
normalized_df = (
    utils.add_is_new_src_ip_feature(
        normalized_df
    )
)

# first time message seen
normalized_df = (
    utils.add_is_new_message_pattern_feature(
        normalized_df
    )
)

# previous message from same source ip
normalized_df = (
    utils.add_previous_message_per_ip(
        normalized_df
    )
)

# length of message
normalized_df = (
    utils.add_message_length_feature(
        normalized_df
    )
)

# ratio of digits in message
normalized_df = (
    utils.add_digit_ratio_feature(
        normalized_df
    )
)

# ratio of special characters in message
normalized_df = (
    utils.add_special_char_ratio_feature(
        normalized_df
    )
)

# whether source ip is internal/private
normalized_df = (
    utils.add_is_internal_ip_feature(
        normalized_df
    )
)

print("\n")
print("=" * 80)
print("=" * 80)     
print(normalized_df.tail(60) )
