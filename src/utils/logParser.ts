export interface ParsedLogEntry {
  ip: string;
  timestamp: string;
  method: string;
  path: string;
  protocol: string;
  status: string;
  bytes: string;
  referrer: string;
  user_agent: string;
  host: string;
  server_ip: string;
}

const LOG_PATTERN = /(?<ip>\S+) - - \[(?<timestamp>.*?)\] "(?<method>\S+) (?<path>\S+) (?<protocol>[^"]+)" (?<status>\d{3}) (?<bytes>\S+) "(?<referrer>[^"]*)" "(?<user_agent>[^"]*)" (?<host>\S+) (?<server_ip>\S+)/;

function parseTimestamp(timestamp: string): string {
  // Convert timestamp from log format to ISO string or keep as is
  // Example: "10/Oct/2023:13:55:36 +0000" -> standardized format
  try {
    // Parse common log format timestamp
    const date = new Date(timestamp.replace(/(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})/, '$3-$2-$1T$4:$5:$6$7'));
    return date.toISOString();
  } catch {
    // If parsing fails, return original timestamp
    return timestamp;
  }
}

export function parseLogFile(content: string): ParsedLogEntry[] {
  const lines = content.split('\n');
  const parsed: ParsedLogEntry[] = [];

  for (const line of lines) {
    const match = line.match(LOG_PATTERN);
    if (match && match.groups) {
      parsed.push({
        ip: match.groups.ip,
        timestamp: parseTimestamp(match.groups.timestamp),
        method: match.groups.method,
        path: match.groups.path,
        protocol: match.groups.protocol,
        status: match.groups.status,
        bytes: match.groups.bytes,
        referrer: match.groups.referrer,
        user_agent: match.groups.user_agent,
        host: match.groups.host,
        server_ip: match.groups.server_ip,
      });
    }
  }

  return parsed;
}

export function convertToDataFrame(entries: ParsedLogEntry[]) {
  // Convert to a structure similar to pandas DataFrame
  const df: Record<string, any[]> = {
    ip: [],
    timestamp: [],
    method: [],
    path: [],
    protocol: [],
    status: [],
    bytes: [],
    referrer: [],
    user_agent: [],
    host: [],
    server_ip: [],
  };

  entries.forEach(entry => {
    df.ip.push(entry.ip);
    df.timestamp.push(entry.timestamp);
    df.method.push(entry.method);
    df.path.push(entry.path);
    df.protocol.push(entry.protocol);
    df.status.push(entry.status);
    df.bytes.push(entry.bytes === '-' ? '0' : entry.bytes);
    df.referrer.push(entry.referrer);
    df.user_agent.push(entry.user_agent);
    df.host.push(entry.host);
    df.server_ip.push(entry.server_ip);
  });

  return df;
}