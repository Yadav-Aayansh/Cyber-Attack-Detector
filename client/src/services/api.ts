import { ApiResponse, LogEntry, ScanEndpoint, ScanParams } from '../types';

const API_BASE_URL = 'http://127.0.0.1:6969';

class ApiService {
  private async makeRequest<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    try {
      const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        headers: {
          'Accept': 'application/json',
          ...options.headers,
        },
        ...options,
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error('API request failed:', error);
      throw error;
    }
  }

  async scanLogs(
    scanType: ScanEndpoint,
    params: ScanParams
  ): Promise<ApiResponse<LogEntry>> {
    const formData = new FormData();
    formData.append('file', params.file);

    const searchParams = new URLSearchParams();
    if (params.limit) searchParams.append('limit', params.limit.toString());
    if (params.offset) searchParams.append('offset', params.offset.toString());

    const queryString = searchParams.toString();
    const url = `/api/scan/${scanType}${queryString ? `?${queryString}` : ''}`;

    return this.makeRequest<ApiResponse<LogEntry>>(url, {
      method: 'POST',
      body: formData,
    });
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
  async scanAllTypes(file: File, limit = 500, offset = 0): Promise<{
    [K in ScanEndpoint]: ApiResponse<LogEntry>;
  }> {
    const params = { file, limit, offset };
    
    const [
      sqlInjection,
      pathTraversal,
      bots,
      lfiRfi,
      wpProbe,
      bruteForce,
      errors,
      internalIp
    ] = await Promise.all([
      this.scanSqlInjection(params),
      this.scanPathTraversal(params),
      this.scanBots(params),
      this.scanLfiRfi(params),
      this.scanWpProbe(params),
      this.scanBruteForce(params),
      this.scanErrors(params),
      this.scanInternalIp(params),
    ]);

    return {
      'sql-injection': sqlInjection,
      'path-traversal': pathTraversal,
      'bots': bots,
      'lfi-rfi': lfiRfi,
      'wp-probe': wpProbe,
      'brute-force': bruteForce,
      'errors': errors,
      'internal-ip': internalIp,
    };
  }
}

export const apiService = new ApiService();