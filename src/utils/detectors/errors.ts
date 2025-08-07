import { ParsedLogEntry } from '../logParser';

export function detectErrors(entries: ParsedLogEntry[]): ParsedLogEntry[] {
  const badStatuses = ['403', '404', '406', '500', '502'];

  const errors = entries.filter(entry => {
    return badStatuses.includes(entry.status);
  });

  return errors.map(entry => ({
    ...entry,
    suspicion_reason: `HTTP error status: ${entry.status}`
  }));
}