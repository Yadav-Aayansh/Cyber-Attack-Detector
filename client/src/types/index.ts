// API Response Types
export interface ApiResponse<T> {
  count: number;
  is_more: boolean;
  results: T;
}

// Log Entry Structure
export interface LogEntry {
  ip: string[];
  timestamp: string[];
  method: string[];
  path: string[];
  protocol: string[];
  status: number[];
  bytes: number[];
  referrer: string[];
  user_agent: string[];
  host: string[];
  server_ip: string[];
  suspicion_reason?: string[];
}

// Processed Log Entry for Display
export interface ProcessedLogEntry {
  ip: string;
  timestamp: string;
  method: string;
  path: string;
  protocol: string;
  status: number;
  bytes: number;
  referrer: string;
  user_agent: string;
  host: string;
  server_ip: string;
  suspicion_reason: string;
  attack_type: string;
}

// API Endpoints
export type ScanEndpoint = 
  | 'sql-injection'
  | 'path-traversal' 
  | 'bots'
  | 'lfi-rfi'
  | 'wp-probe'
  | 'brute-force'
  | 'errors'
  | 'internal-ip';

// Scan Request Parameters
export interface ScanParams {
  file: File;
  limit?: number;
  offset?: number;
}

// Filter State
export interface Filters {
  attackType: string;
  statusCode: string;
  ip: string;
  dateRange: string;
  severity: string;
  search: string;
}

// Toast Notification
export interface Toast {
  id: number;
  message: string;
  type: 'success' | 'error' | 'info' | 'warning';
}

// Analysis Summary
export interface AnalysisSummary {
  totalThreats: number;
  attackTypeCounts: Record<string, number>;
  topAttackers: Array<{ ip: string; count: number; }>;
  statusCodeDistribution: Record<string, number>;
  timelineData: Array<{ date: string; count: number; }>;
}

// Saved Analysis
export interface SavedAnalysis {
  id: number;
  name: string;
  uploadDate: string;
  summary: AnalysisSummary;
  results: ProcessedLogEntry[];
}

// Theme Type
export type Theme = 'light' | 'dark';

// Attack Type Configuration
export interface AttackTypeConfig {
  name: string;
  description: string;
  severity: 'high' | 'medium' | 'low';
  color: string;
  endpoint: ScanEndpoint;
}