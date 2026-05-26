import pandas as pd
import ipaddress
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import TruncatedSVD


# TIME NORMALIZATION


def add_unix_timestamp_column(
    df,
    time_col="time",
    new_col="unix_time"
):

    df = df.copy()

    # convert to datetime
    dt = pd.to_datetime(
        df[time_col],
        errors="coerce"
    )

    # Add debugging to see what's happening
    # dt = pd.to_datetime(df[time_col], errors="coerce")
    # print("Datetime64 values:")
    # print(dt)
    # print("\nNanoseconds since epoch:")
    # print(dt.astype("int64"))



    # convert datetime -> unix seconds
    df[new_col] = (
        dt.astype("int64") // 10**6
    )

    return df




# we will be needing to identify each unique IP address in the dataset, and convert them to categorical ids. 
# important for ml later
def encode_ip_column(
    df,
    column_name,
    new_column=None
):

    df = df.copy()

    if new_column is None:
        new_column = f"{column_name}_encoded"

    # convert to categorical ids
    df[new_column] = (
        pd.Categorical(df[column_name])
        .codes
    )

    return df


# tf-idf encoding of the text field(message)

from sklearn.feature_extraction.text import TfidfVectorizer
import pandas as pd


def encode_message_semantics(
    df,
    text_column="message",
    n_components=5
):

    df = df.copy()

    text_data = (
        df[text_column]
        .fillna("")
        .astype(str)
    )

    # character-level tfidf
    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5)
    )

    tfidf_matrix = vectorizer.fit_transform(text_data)

    # reduce dimensions
    svd = TruncatedSVD(
        n_components=n_components,
        random_state=42
    )

    reduced = svd.fit_transform(tfidf_matrix)

    # create dense columns
    reduced_df = pd.DataFrame(
        reduced,
        columns=[
            f"{text_column}_semantic_{i}"
            for i in range(n_components)
        ]
    )

    df = df.reset_index(drop=True)
    reduced_df = reduced_df.reset_index(drop=True)

    df = pd.concat(
        [df, reduced_df],
        axis=1
    )

    return df, vectorizer, svd











########################
########################
# above was normalizing, below is features
########################
########################

# number of logs(rows) in the last 30 minutes

import pandas as pd
def add_logs_last_time_window_feature(
    df,
    minutes=30,
    time_col="unix_time",
    new_col=None
):

    df = df.copy()

    if new_col is None:
        new_col = f"logs_last_{minutes}min"

    # sort by time
    df = df.sort_values(time_col)

    # convert unix milliseconds -> datetime
    dt = pd.to_datetime(
        df[time_col],
        unit="ms"
    )

    df.index = dt

    # rolling count
    rolling_counts = (
        df[time_col]
        .rolling(f"{minutes}min")
        .count()
    )

    df[new_col] = rolling_counts.values

    df = df.reset_index(drop=True)

    return df

# how long ago did it take for 200 logs to arrive prior to the  current one?


def add_time_for_previous_n_logs(
    df,
    time_col="unix_time",
    n=200,
    new_col=None
):

    df = df.copy()

    if new_col is None:
        new_col = f"time_for_previous_{n}_logs"

    
    # shifted timestamp
    previous_times = (
        df[time_col]
        .shift(n)
    )

    # difference in seconds
    df[new_col] = (
        df[time_col] - previous_times
    )

    return df


import pandas as pd
import numpy as np
import ipaddress
import re


###############################################################################
# SOURCE IP LOG COUNTS OVER TIME WINDOWS
###############################################################################

def add_src_ip_logs_last_time_window_feature(
    df,
    minutes=5,
    src_ip_col="src_ip",
    time_col="unix_time",
    new_col=None
):

    df = df.copy()

    if new_col is None:
        new_col = f"src_ip_logs_last_{minutes}min"

    # sort by time
    df = df.sort_values(time_col)

    # convert unix milliseconds -> datetime
    dt = pd.to_datetime(
        df[time_col],
        unit="ms"
    )

    df["_dt"] = dt

    result = []

    for src_ip, group in df.groupby(src_ip_col):

        group = group.sort_values("_dt")

        rolling_counts = (
            group
            .rolling(
                f"{minutes}min",
                on="_dt"
            )[time_col]
            .count()
        )

        result.append(rolling_counts)

    df[new_col] = pd.concat(result).sort_index()

    df = df.drop(columns=["_dt"])

    return df


###############################################################################
# UNIQUE DESTINATION IPS IN LAST TIME WINDOW
###############################################################################

def add_unique_dst_ips_last_time_window(
    df,
    minutes=5,
    src_ip_col="src_ip",
    dst_ip_col="dst_ip",
    time_col="unix_time",
    new_col=None
):

    df = df.copy()

    if new_col is None:
        new_col = f"unique_dst_ips_last_{minutes}min"

    df = df.sort_values(time_col)

    dt = pd.to_datetime(
        df[time_col],
        unit="ms"
    )

    df["_dt"] = dt

    values = []

    for idx, row in df.iterrows():

        current_src = row[src_ip_col]
        current_time = row["_dt"]

        start_time = (
            current_time -
            pd.Timedelta(minutes=minutes)
        )

        mask = (
            (df[src_ip_col] == current_src) &
            (df["_dt"] >= start_time) &
            (df["_dt"] <= current_time)
        )

        unique_count = (
            df.loc[mask, dst_ip_col]
            .nunique()
        )

        values.append(unique_count)

    df[new_col] = values

    df = df.drop(columns=["_dt"])

    return df


###############################################################################
# TIME SINCE LAST EVENT FROM SAME SOURCE IP
###############################################################################

def add_time_since_last_src_ip_event(
    df,
    src_ip_col="src_ip",
    time_col="unix_time",
    new_col="time_since_last_src_ip_event"
):

    df = df.copy()

    df = df.sort_values(time_col)

    previous_times = (
        df.groupby(src_ip_col)[time_col]
        .shift(1)
    )

    df[new_col] = (
        df[time_col] - previous_times
    )

    return df


###############################################################################
# MESSAGE FREQUENCY
###############################################################################

def add_message_frequency_feature(
    df,
    text_col="message",
    new_col="message_frequency"
):

    df = df.copy()

    frequencies = (
        df[text_col]
        .value_counts()
    )

    df[new_col] = (
        df[text_col]
        .map(frequencies)
    )

    return df


###############################################################################
# SOURCE IP FREQUENCY
###############################################################################

def add_src_ip_frequency_feature(
    df,
    src_ip_col="src_ip",
    new_col="src_ip_frequency"
):

    df = df.copy()

    frequencies = (
        df[src_ip_col]
        .value_counts()
    )

    df[new_col] = (
        df[src_ip_col]
        .map(frequencies)
    )

    return df


###############################################################################
# IS NEW SOURCE IP
###############################################################################

def add_is_new_src_ip_feature(
    df,
    src_ip_col="src_ip",
    new_col="is_new_src_ip"
):

    df = df.copy()

    seen = set()

    values = []

    for ip in df[src_ip_col]:

        if ip in seen:
            values.append(0)

        else:
            values.append(1)
            seen.add(ip)

    df[new_col] = values

    return df


###############################################################################
# IS NEW MESSAGE PATTERN
###############################################################################

def add_is_new_message_pattern_feature(
    df,
    text_col="message",
    new_col="is_new_message_pattern"
):

    df = df.copy()

    seen = set()

    values = []

    for msg in df[text_col]:

        if msg in seen:
            values.append(0)

        else:
            values.append(1)
            seen.add(msg)

    df[new_col] = values

    return df


###############################################################################
# PREVIOUS MESSAGE FROM SAME SOURCE IP
###############################################################################

def add_previous_message_per_ip(
    df,
    src_ip_col="src_ip",
    text_col="message",
    time_col="unix_time",
    new_col="previous_message"
):

    df = df.copy()

    df = df.sort_values(time_col)

    df[new_col] = (
        df.groupby(src_ip_col)[text_col]
        .shift(1)
    )

    return df


###############################################################################
# MESSAGE LENGTH
###############################################################################

def add_message_length_feature(
    df,
    text_col="message",
    new_col="message_length"
):

    df = df.copy()

    df[new_col] = (
        df[text_col]
        .fillna("")
        .astype(str)
        .str.len()
    )

    return df


###############################################################################
# DIGIT RATIO
###############################################################################

def add_digit_ratio_feature(
    df,
    text_col="message",
    new_col="digit_ratio"
):

    df = df.copy()

    def compute_ratio(text):

        text = str(text)

        if len(text) == 0:
            return 0

        digit_count = sum(
            c.isdigit()
            for c in text
        )

        return digit_count / len(text)

    df[new_col] = (
        df[text_col]
        .apply(compute_ratio)
    )

    return df


###############################################################################
# SPECIAL CHARACTER RATIO
###############################################################################

def add_special_char_ratio_feature(
    df,
    text_col="message",
    new_col="special_char_ratio"
):

    df = df.copy()

    def compute_ratio(text):

        text = str(text)

        if len(text) == 0:
            return 0

        special_count = sum(
            not c.isalnum() and not c.isspace()
            for c in text
        )

        return special_count / len(text)

    df[new_col] = (
        df[text_col]
        .apply(compute_ratio)
    )

    return df


###############################################################################
# INTERNAL IP FEATURE
###############################################################################

def add_is_internal_ip_feature(
    df,
    src_ip_col="src_ip",
    new_col="is_internal_ip"
):

    df = df.copy()

    def is_internal(ip):

        try:
            return int(
                ipaddress.ip_address(ip).is_private
            )

        except:
            return 0

    df[new_col] = (
        df[src_ip_col]
        .apply(is_internal)
    )

    return df


