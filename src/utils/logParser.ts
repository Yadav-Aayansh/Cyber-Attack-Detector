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
  // Convert timestamp from log format to ISO string
  // Example: "30/Apr/2024:07:12:09 -0500" -> ISO format
  try {
    // Parse common log format timestamp: DD/MMM/YYYY:HH:MM:SS TIMEZONE
    const match = timestamp.match(/(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})/);
    if (!match) {
      return timestamp;
    }
    
    const [, day, monthName, year, hour, minute, second, timezone] = match;
    
    // Convert month name to number
    const monthMap: Record<string, string> = {
      'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04',
      'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
      'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'
    };
    
    const month = monthMap[monthName];
    if (!month) {
      return timestamp;
    }
    
    // Create ISO format string: YYYY-MM-DDTHH:MM:SS+TIMEZONE
    const isoString = `${year}-${month}-${day}T${hour}:${minute}:${second}${timezone}`;
    
    // Validate the date by creating a Date object
    const date = new Date(isoString);
    if (isNaN(date.getTime())) {
      return timestamp;
    }
    
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
