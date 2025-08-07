import { ParsedLogEntry } from '../logParser';

export function detectBruteForce(entries: ParsedLogEntry[]): ParsedLogEntry[] {
  const loginPattern = /(login|admin|signin|wp-login\.php)/i;
  const badStatuses = ['401', '403', '429'];

  const suspicious = entries.filter(entry => {
    return loginPattern.test(entry.path) && badStatuses.includes(entry.status);
  });

  return suspicious.map(entry => ({
    ...entry,
    suspicion_reason: 'Brute force attempt detected'
  }));
}