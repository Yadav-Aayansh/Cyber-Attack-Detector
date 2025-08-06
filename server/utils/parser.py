import re

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) - - \[(?P<timestamp>.*?)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<bytes>\S+) '
    r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)" '
    r'(?P<host>\S+) (?P<server_ip>\S+)'
)

def parse_logs(raw_lines):
    parsed = []
    for line in raw_lines:
        match = LOG_PATTERN.match(line)
        if match:
            parsed.append(match.groupdict())
    return parsed
