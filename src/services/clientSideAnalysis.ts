import { parseLogFile, ParsedLogEntry } from '../utils/logParser';
import { DETECTORS, DetectorKey } from '../utils/detectors';
import { ProcessedLogEntry } from '../types';

export interface AnalysisResult {
  count: number;
  is_more: boolean;
  results: ProcessedLogEntry[];
}

export class ClientSideAnalysisService {
  private parsedEntries: ParsedLogEntry[] = [];

  async loadLogFile(file: File): Promise<void> {
    const content = await file.text();
    this.parsedEntries = parseLogFile(content);
  }

  analyzeWithDetector(detectorKey: DetectorKey, limit: number = 500, offset: number = 0): AnalysisResult {
    const detector = DETECTORS[detectorKey];
    const suspicious = detector(this.parsedEntries);
    
    // Convert to ProcessedLogEntry format
    const processedEntries: ProcessedLogEntry[] = suspicious.map(entry => ({
      ip: entry.ip,
      timestamp: entry.timestamp,
      method: entry.method,
      path: entry.path,
      protocol: entry.protocol,
      status: parseInt(entry.status, 10),
      bytes: parseInt(entry.bytes === '-' ? '0' : entry.bytes, 10),
      referrer: entry.referrer,
      user_agent: entry.user_agent,
      host: entry.host,
      server_ip: entry.server_ip,
      suspicion_reason: entry.suspicion_reason || '',
      attack_type: this.getAttackTypeName(detectorKey),
    }));

    return {
      count: processedEntries.length,
      is_more: false,
      results: processedEntries,
    };
  }

  private getAttackTypeName(detectorKey: DetectorKey): string {
    const nameMap: Record<DetectorKey, string> = {
      'sql-injection': 'SQL Injection',
      'path-traversal': 'Path Traversal',
      'bots': 'Bot Detection',
      'lfi-rfi': 'LFI/RFI Attacks',
      'wp-probe': 'WordPress Probes',
      'brute-force': 'Brute Force',
      'errors': 'HTTP Errors',
      'internal-ip': 'Internal IP Access',
    };
    return nameMap[detectorKey];
  }

  // Batch analyze all types
  analyzeAllTypes(): Record<DetectorKey, AnalysisResult> {
    const results: Record<string, AnalysisResult> = {};
    
    Object.keys(DETECTORS).forEach(key => {
      const detectorKey = key as DetectorKey;
      results[detectorKey] = this.analyzeWithDetector(detectorKey);
    });

    return results as Record<DetectorKey, AnalysisResult>;
  }

  getTotalEntries(): number {
    return this.parsedEntries.length;
  }

  clear(): void {
    this.parsedEntries = [];
  }

  getParsedEntries(): ParsedLogEntry[] {
    return this.parsedEntries;
  }
}

// Create a singleton instance
export const clientAnalysisService = new ClientSideAnalysisService();