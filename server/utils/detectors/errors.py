import pandas as pd

def detect_errors(df: pd.DataFrame) -> pd.DataFrame:
    if 'status' not in df:
        return pd.DataFrame()

    bad_statuses = ['403', '404', '406', '500', '502']

    errors = df[df['status'].astype(str).isin(bad_statuses)]

    return errors[[
        "ip", "timestamp", "method", "path", "status", "user_agent"
    ]]
