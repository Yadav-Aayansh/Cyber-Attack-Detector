import { ParsedLogEntry } from '../logParser';

export function detectWpProbe(entries: ParsedLogEntry[]): ParsedLogEntry[] {
  const pattern = /(\.php|\/wp-|xmlrpc\.php|\?author=|\?p=)/i;

  const suspicious = entries.filter(entry => {
    return pattern.test(entry.path);
  });

  return suspicious.map(entry => ({
    ...entry,
    suspicion_reason: 'WordPress probe detected'
  }));
}