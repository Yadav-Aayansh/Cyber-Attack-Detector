import pandas as pd

def detect_internal_ip(df: pd.DataFrame) -> pd.DataFrame:
    if 'ip' not in df:
        return pd.DataFrame()

    internal_ranges = (
        df['ip'].str.startswith('192.168.') |
        df['ip'].str.startswith('10.') |
        df['ip'].str.startswith('127.') |
        df['ip'].str.startswith('172.')
    )

    internal = df[internal_ranges]

    return internal[[
        "ip", "timestamp", "method", "path", "status", "user_agent"
    ]]
