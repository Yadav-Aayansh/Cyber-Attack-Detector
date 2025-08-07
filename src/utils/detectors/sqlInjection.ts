import { ParsedLogEntry } from '../logParser';

export class AdvancedSQLInjectionDetector {
  private patterns: string[];
  private sqliRegex: RegExp;
  private whitelistPatterns: string[];
  private whitelistRegex: RegExp;

  constructor() {
    // Common SQL injection patterns
    this.patterns = [
      // Union-based injections
      "union\\s+(all\\s+)?select",
      "select\\s+.*\\s+from",
      "select\\s+\\*",
      
      // Boolean-based blind injections
      "(and|or)\\s+\\d+\\s*[=<>!]+\\s*\\d+",
      "(and|or)\\s+['\\\"]?[a-z]+['\\\"]?\\s*[=<>!]+\\s*['\\\"]?[a-z]+['\\\"]?",
      "(and|or)\\s+\\d+\\s*(and|or)\\s+\\d+",
      
      // Time-based blind injections
      "(sleep|waitfor|delay)\\s*\\(\\s*\\d+\\s*\\)",
      "benchmark\\s*\\(\\s*\\d+",
      "pg_sleep\\s*\\(\\s*\\d+\\s*\\)",
      
      // Error-based injections
      "(convert|cast|char)\\s*\\(",
      "concat\\s*\\(",
      "group_concat\\s*\\(",
      "having\\s+\\d+\\s*[=<>!]+\\s*\\d+",
      
      // Authentication bypass
      "(admin|user|login)['\\\"]?\\s*(=|like)\\s*['\\\"]?\\s*(or|and)",
      "['\\\"]\\s*(or|and)\\s*['\\\"]?[^'\\\"]*['\\\"]?\\s*(=|like)",
      "['\\\"]\\s*(or|and)\\s*\\d+\\s*[=<>!]+\\s*\\d+",
      
      // SQL commands and functions
      "(drop|delete|truncate|insert|update)\\s+(table|from|into)",
      "(exec|execute|sp_|xp_)\\w*",
      "(information_schema|sys\\.|mysql\\.|pg_)",
      "(load_file|into\\s+outfile|dumpfile)",
      
      // Comment patterns
      "(--|#|\\*/|\\*\\*)",
      "/\\*.*\\*/",
      
      // Special characters and encodings
      "(%27|%22|%2d%2d|%23)",
      "(0x[0-9a-f]+)",
      "(char\\s*\\(\\s*\\d+)",
      
      // LDAP injection patterns
      "(\\*\\)|(&\\()|(\\|\\())",
      
      // XML injection
      "(<script|<iframe|javascript:|vbscript:)",
      
      // Command injection
      "(;|\\|&|&&|\\|\\|).*(cat|ls|dir|type|echo|ping|nslookup|whoami)",
      
      // Path traversal that might be combined with SQLi
      "(\\.\\./)\\{2,\\}",
      
      // NoSQL injection patterns
      "(\\$ne|\\$gt|\\$lt|\\$regex|\\$where)",
    ];
    
    this.sqliRegex = new RegExp(
      this.patterns.map(pattern => `(${pattern})`).join('|'),
      'gim'
    );
    
    this.whitelistPatterns = [
      "^/[a-z]+mp3/",
      "^/blog/",
      "^/images/",
      "^/css/",
      "^/js/",
      "^/api/v\\d+/",
    ];
    
    this.whitelistRegex = new RegExp(
      this.whitelistPatterns.map(pattern => `(${pattern})`).join('|'),
      'i'
    );
  }

  private decodeUrl(url: string): string {
    try {
      return decodeURIComponent(url);
    } catch {
      return url;
    }
  }

  private isSuspiciousPath(path: string): boolean {
    if (!path) return false;
    
    const decodedPath = this.decodeUrl(path);
    
    if (this.whitelistRegex.test(path)) {
      const obviousPatterns = [
        "union\\s+select",
        "(and|or)\\s+\\d+\\s*=\\s*\\d+",
        "['\\\"]\\s*or\\s*['\\\"]?\\d",
        "drop\\s+table",
        "script\\s*:",
        "javascript\\s*:",
      ];
      const obviousRegex = new RegExp(obviousPatterns.join('|'), 'i');
      return obviousRegex.test(decodedPath);
    }
    
    return this.sqliRegex.test(decodedPath);
  }

  public getMatchedPatterns(path: string): string[] {
    if (!path) return [];
    
    const decodedPath = this.decodeUrl(path);
    const matches: string[] = [];
    
    this.patterns.forEach((pattern, i) => {
      const regex = new RegExp(pattern, 'i');
      if (regex.test(decodedPath)) {
        matches.push(`Pattern_${i + 1}: ${pattern}`);
      }
    });
    
    return matches;
  }

  public detectSqlInjection(entries: ParsedLogEntry[]): ParsedLogEntry[] {
    const suspicious = entries.filter(entry => this.isSuspiciousPath(entry.path));
    
    // Add matched patterns for debugging
    return suspicious.map(entry => ({
      ...entry,
      suspicion_reason: this.getMatchedPatterns(entry.path).join('; ')
    }));
  }
}

export function detectSqlInjection(entries: ParsedLogEntry[]): ParsedLogEntry[] {
  const detector = new AdvancedSQLInjectionDetector();
  return detector.detectSqlInjection(entries);
}