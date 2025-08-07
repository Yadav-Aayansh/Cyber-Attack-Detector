import { ParsedLogEntry } from '../logParser';

export function detectInternalIp(entries: ParsedLogEntry[]): ParsedLogEntry[] {
  const internal = entries.filter(entry => {
    const ip = entry.ip;
    return ip.startsWith('192.168.') ||
           ip.startsWith('10.') ||
           ip.startsWith('127.') ||
           ip.startsWith('172.');
  });

  return internal.map(entry => ({
    ...entry,
    suspicion_reason: 'Internal IP address detected'
  }));
}