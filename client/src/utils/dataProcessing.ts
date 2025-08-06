import { LogEntry, ProcessedLogEntry, AnalysisSummary } from '../types';
import { ATTACK_TYPES } from '../config/attackTypes';

export function processLogData(
  data: any,
  attackType: string
): ProcessedLogEntry[] {
  if (
    !data ||
    typeof data !== 'object' ||
    !Array.isArray(data.ip) ||
    data.ip.length === 0
  ) {
    return [];
  }

  const {
    ip = [],
    timestamp = [],
    method = [],
    path = [],
    protocol = [],
    status = [],
    bytes = [],
    referrer = [],
    user_agent = [],
    host = [],
    server_ip = [],
    suspicion_reason = []
  } = data;

  const length = ip.length;
  const entries: ProcessedLogEntry[] = [];

  for (let i = 0; i < length; i++) {
    entries.push({
      ip: ip[i] || '',
      timestamp: timestamp[i] || '',
      method: method[i] || '',
      path: path[i] || '',
      protocol: protocol[i] || '',
      status: status[i] || 0,
      bytes: bytes[i] || 0,
      referrer: referrer[i] || '',
      user_agent: user_agent[i] || '',
      host: host[i] || '',
      server_ip: server_ip[i] || '',
      suspicion_reason: suspicion_reason[i] || '',
      attack_type: attackType,
    });
  }

  return entries;
}

export function generateAnalysisSummary(
  allResults: ProcessedLogEntry[]
): AnalysisSummary {
  const attackTypeCounts: Record<string, number> = {};
  const ipCounts: Record<string, number> = {};
  const statusCodeCounts: Record<string, number> = {};
  const dailyCounts: Record<string, number> = {};

  for (const entry of allResults) {
    // Attack type counts
    attackTypeCounts[entry.attack_type] = (attackTypeCounts[entry.attack_type] || 0) + 1;

    // IP counts
    ipCounts[entry.ip] = (ipCounts[entry.ip] || 0) + 1;

    // Status code counts
    const statusCode = entry.status.toString();
    statusCodeCounts[statusCode] = (statusCodeCounts[statusCode] || 0) + 1;

    // Daily counts
    const ts = entry.timestamp;
    if (ts && !isNaN(Date.parse(ts))) {
      const date = new Date(ts).toISOString().split('T')[0];
      dailyCounts[date] = (dailyCounts[date] || 0) + 1;
    }
  }

  const topAttackers = Object.entries(ipCounts)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 10)
    .map(([ip, count]) => ({ ip, count }));

  const timelineData = Object.entries(dailyCounts)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([date, count]) => ({ date, count }));

  return {
    totalThreats: allResults.length,
    attackTypeCounts,
    topAttackers,
    statusCodeDistribution: statusCodeCounts,
    timelineData,
  };
}

export function exportToCSV(data: ProcessedLogEntry[]): string {
  const headers = [
    'IP',
    'Timestamp',
    'Method',
    'Path',
    'Protocol',
    'Status',
    'Bytes',
    'Referrer',
    'User Agent',
    'Host',
    'Server IP',
    'Suspicion Reason',
    'Attack Type'
  ];

  const csvContent = [
    headers.join(','),
    ...data.map(row => [
      row.ip,
      row.timestamp,
      row.method,
      `"${row.path.replace(/"/g, '""')}"`,
      row.protocol,
      row.status,
      row.bytes,
      `"${row.referrer.replace(/"/g, '""')}"`,
      `"${row.user_agent.replace(/"/g, '""')}"`,
      row.host,
      row.server_ip,
      `"${row.suspicion_reason.replace(/"/g, '""')}"`,
      row.attack_type
    ].join(','))
  ].join('\n');

  return csvContent;
}

export function exportToJSON(data: ProcessedLogEntry[]): string {
  return JSON.stringify(data, null, 2);
}

export function downloadFile(content: string, filename: string, contentType: string) {
  const blob = new Blob([content], { type: contentType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
