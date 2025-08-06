import re
import pandas as pd

def detect_brute_force(df: pd.DataFrame) -> pd.DataFrame:
    if 'path' not in df or 'status' not in df:
        return pd.DataFrame()

    login_keywords = r"(login|admin|signin|wp-login\.php)"
    bad_statuses = ['401', '403', '429']

    suspicious = df[
        df['path'].str.contains(login_keywords, case=False, na=False) &
        df['status'].astype(str).isin(bad_statuses)
    ]

    return suspicious[[
        "ip", "timestamp", "method", "path", "status", "user_agent"
    ]]
