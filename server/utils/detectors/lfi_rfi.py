import re
import pandas as pd

def detect_lfi_rfi(df: pd.DataFrame) -> pd.DataFrame:
    if 'path' not in df:
        return pd.DataFrame()

    pattern = re.compile(r"(etc/passwd|proc/self/environ|input_file=|data:text)", re.IGNORECASE)

    filtered = df[df['path'].str.contains(pattern, na=False)]

    return filtered[[
        "ip", "timestamp", "method", "path", "status", "user_agent"
    ]]
