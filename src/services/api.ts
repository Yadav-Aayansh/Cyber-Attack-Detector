import { ApiResponse, LogEntry, ScanEndpoint, ScanParams, ProcessedLogEntry } from '../types';
import { clientAnalysisService, AnalysisResult } from './clientSideAnalysis';
import { processLogData } from '../utils/dataProcessing';

class ApiService {
  // Now using client-side analysis instead of server requests
  private convertToApiResponse(result: AnalysisResult): ApiResponse<LogEntry> {
    // Convert ProcessedLogEntry[] back to LogEntry format for compatibility
    const logEntry: LogEntry = {
      ip: result.results.map(r => r.ip),
      timestamp: result.results.map(r => r.timestamp),
      method: result.results.map(r => r.method),
      path: result.results.map(r => r.path),
      protocol: result.results.map(r => r.protocol),
      status: result.results.map(r => r.status),
      bytes: result.results.map(r => r.bytes),
      referrer: result.results.map(r => r.referrer),
      user_agent: result.results.map(r => r.user_agent),
      host: result.results.map(r => r.host),
      server_ip: result.results.map(r => r.server_ip),
      suspicion_reason: result.results.map(r => r.suspicion_reason),
    };

    return {
      count: result.count,
      is_more: result.is_more,
      results: logEntry,
    };
  }

  async scanLogs(
    scanType: ScanEndpoint,
    params: ScanParams
  ): Promise<ApiResponse<LogEntry>> {
    // Load the file into the client-side analysis service
    await clientAnalysisService.loadLogFile(params.file);
    
    // Run the analysis client-side
    const result = clientAnalysisService.analyzeWithDetector(scanType);
    
    // Convert to the expected API response format
    return this.convertToApiResponse(result);
  }

  // Convenience methods for each scan type
  async scanSqlInjection(params: ScanParams) {
    return this.scanLogs('sql-injection', params);
  }

  async scanPathTraversal(params: ScanParams) {
    return this.scanLogs('path-traversal', params);
  }

  async scanBots(params: ScanParams) {
    return this.scanLogs('bots', params);
  }

  async scanLfiRfi(params: ScanParams) {
    return this.scanLogs('lfi-rfi', params);
  }

  async scanWpProbe(params: ScanParams) {
    return this.scanLogs('wp-probe', params);
  }

  async scanBruteForce(params: ScanParams) {
    return this.scanLogs('brute-force', params);
  }

  async scanErrors(params: ScanParams) {
    return this.scanLogs('errors', params);
  }

  async scanInternalIp(params: ScanParams) {
    return this.scanLogs('internal-ip', params);
  }

  // Batch scan all types
  async scanAllTypes(file: File): Promise<{
    [K in ScanEndpoint]: ApiResponse<LogEntry>;
  }> {
    // Load the file once
    await clientAnalysisService.loadLogFile(file);
    
    // Run all analyses
    const results = clientAnalysisService.analyzeAllTypes();

    return {
      'sql-injection': this.convertToApiResponse(results['sql-injection']),
      'path-traversal': this.convertToApiResponse(results['path-traversal']),
      'bots': this.convertToApiResponse(results['bots']),
      'lfi-rfi': this.convertToApiResponse(results['lfi-rfi']),
      'wp-probe': this.convertToApiResponse(results['wp-probe']),
      'brute-force': this.convertToApiResponse(results['brute-force']),
      'errors': this.convertToApiResponse(results['errors']),
      'internal-ip': this.convertToApiResponse(results['internal-ip']),
    };
  }
}

export const apiService = new ApiService();
