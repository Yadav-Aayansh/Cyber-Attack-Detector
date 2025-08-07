import { ParsedLogEntry } from '../logParser';

export function detectPathTraversal(entries: ParsedLogEntry[]): ParsedLogEntry[] {
  const suspicious = entries.filter(entry => {
    const path = entry.path;
    if (!path) return false;

    // Check for path traversal patterns
    const hasTraversalPattern = new RegExp('(\\.\\./|%2e%2e%2f|%2e%2f|%2f\\.\\.|/\\.{2})', 'i').test(path);
    
    // Check for excessive directory depth
    const hasExcessiveDepth = (path.match(/\//g) || []).length > 15;
    
    return hasTraversalPattern || hasExcessiveDepth;
  });

  return suspicious.map(entry => ({
    ...entry,
    suspicion_reason: 'Path traversal pattern detected'
  }));
}