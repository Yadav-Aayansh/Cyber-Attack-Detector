import pandas as pd

CRAWLERS = [
    'googlebot', 'bingbot', 'baiduspider', 'yandexbot',
    'duckduckbot', 'slurp', 'facebookexternalhit', 'twitterbot',
    'applebot', 'linkedinbot', 'petalbot', 'semrushbot'
]

CLIENT_LIBS = [
    'curl', 'wget', 'httpclient', 'python-requests', 'aiohttp',
    'okhttp', 'java/', 'libwww-perl', 'go-http-client', 'restsharp',
    'scrapy', 'httpie'
]

def classify_user_agent(ua: str):
    ua = ua.lower()
    if any(c in ua for c in CRAWLERS):
        return "Crawler Bot"
    if any(lib in ua for lib in CLIENT_LIBS):
        return "Client Library Bot"
    if ua.strip() == '' or len(ua) < 10 or 'mozilla' not in ua:
        return "Suspicious User-Agent"
    return None

def detect_bots(df: pd.DataFrame) -> pd.DataFrame:
    if 'user_agent' not in df:
        return pd.DataFrame()

    df['bot_type'] = df['user_agent'].apply(classify_user_agent)
    bots = df[df['bot_type'].notnull()]

    return bots[[
        "ip", "timestamp", "path", "status", "user_agent", "bot_type"
    ]]
