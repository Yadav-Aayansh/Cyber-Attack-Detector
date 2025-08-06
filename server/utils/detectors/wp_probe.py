import re
import pandas as pd

def detect_wp_probe(df: pd.DataFrame) -> pd.DataFrame:
    if 'path' not in df:
        return pd.DataFrame()

    suspicious = df[df['path'].str.contains(
        r'(\.php|/wp-|xmlrpc\.php|\?author=|\?p=)',
        case=False, na=False
    )]

    return suspicious[[
        "ip", "timestamp", "method", "path", "status", "user_agent"
    ]]
