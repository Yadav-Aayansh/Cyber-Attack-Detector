import re
import pandas as pd

def detect_path_traversal(df: pd.DataFrame) -> pd.DataFrame:
    if 'path' not in df:
        return pd.DataFrame()

    suspicious = df[df['path'].str.contains(
        r'(\.\./|%2e%2e%2f|%2e%2f|%2f\.\.|/\.{2})', 
        case=False, na=False
    ) | (df['path'].str.count('/') > 15)]

    return suspicious[[
        "ip", "timestamp", "method", "path", "status", "user_agent"
    ]]
