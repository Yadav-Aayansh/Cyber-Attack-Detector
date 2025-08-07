import { ParsedLogEntry } from '../logParser';

export function detectLfiRfi(entries: ParsedLogEntry[]): ParsedLogEntry[] {
  const pattern = /(etc\/passwd|proc\/self\/environ|input_file=|data:text)/i;

  const suspicious = entries.filter(entry => {
    return pattern.test(entry.path);
  });

  return suspicious.map(entry => ({
    ...entry,
    suspicion_reason: 'LFI/RFI pattern detected'
  }));
}