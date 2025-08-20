// Report Generation Service
import { llmService, LLM_PROVIDERS } from './llmService.js';

export class ReportGenerationService {
  async generateReport(allResults, summary, datasetInfo, config) {
    if (!config || !this.canGenerateReport(config)) {
      throw new Error('Invalid report configuration');
    }

    const reportData = this.prepareReportData(allResults, summary, datasetInfo);
    const prompt = this.buildReportPrompt(reportData);

    try {
      const response = await llmService.generateResponse(
        config.providerId,
        prompt,
        config.apiKey,
        config.customEndpoint,
        {
          temperature: 0.3,
          maxTokens: 4000,
        }
      );

      // Clean up the response to remove markdown code block fences
      let cleanedText = response.text.trim();
      
      // Remove markdown code block delimiters if present
      cleanedText = cleanedText.replace(/^```markdown\s*\n?/i, '');
      cleanedText = cleanedText.replace(/^```\s*\n?/i, '');
      cleanedText = cleanedText.replace(/\n?```\s*$/i, '');
      
      // Remove any leading/trailing whitespace after cleanup
      cleanedText = cleanedText.trim();
      
      return {
        markdown: cleanedText,
        usage: response.usage
      };
    } catch (error) {
      console.error('Report generation failed:', error);
      throw new Error(`Failed to generate report: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  prepareReportData(allResults, summary, datasetInfo) {
    // Get top attack types
    const topAttackTypes = Object.entries(summary.attackTypeCounts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 10);

    // Get recent attacks (last 24 hours if timestamps are available)
    const now = new Date();
    const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const recentAttacks = allResults.filter(entry => {
      try {
        const entryDate = new Date(entry.timestamp);
        return entryDate >= oneDayAgo;
      } catch {
        return false;
      }
    });

    // Get most targeted paths
    const pathCounts = {};
    allResults.forEach(entry => {
      pathCounts[entry.path] = (pathCounts[entry.path] || 0) + 1;
    });
    const topPaths = Object.entries(pathCounts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 10);

    // Get attack methods distribution
    const methodCounts = {};
    allResults.forEach(entry => {
      methodCounts[entry.method] = (methodCounts[entry.method] || 0) + 1;
    });

    // Get geographic distribution (based on IP ranges)
    const ipRanges = {};
    allResults.forEach(entry => {
      const ipPrefix = entry.ip.split('.').slice(0, 2).join('.');
      ipRanges[ipPrefix] = (ipRanges[ipPrefix] || 0) + 1;
    });

    return {
      fileName: datasetInfo.fileName || 'Unknown',
      datasetUrl: datasetInfo.datasetUrl || 'Unknown',
      totalThreats: summary.totalThreats,
      uniqueAttackers: summary.topAttackers.length,
      analysisDate: new Date().toISOString(),
      topAttackTypes,
      topAttackers: summary.topAttackers.slice(0, 10),
      recentAttacks: recentAttacks.length,
      topPaths,
      methodCounts: Object.entries(methodCounts).sort(([, a], [, b]) => b - a),
      statusCodeDistribution: summary.statusCodeDistribution,
      criticalFindings: this.identifyCriticalFindings(allResults, summary),
    };
  }

  identifyCriticalFindings(allResults, summary) {
    const findings = [];

    // High-severity attack types with significant activity
    const highSeverityTypes = ['SQL Injection', 'Path Traversal', 'LFI/RFI Attacks', 'Brute Force'];
    highSeverityTypes.forEach(type => {
      const count = summary.attackTypeCounts[type] || 0;
      if (count > 10) {
        findings.push({
          severity: 'HIGH',
          type,
          count,
          description: `Significant ${type.toLowerCase()} activity detected`
        });
      }
    });

    // Top attackers with high activity
    summary.topAttackers.slice(0, 3).forEach(attacker => {
      if (attacker.count > 50) {
        findings.push({
          severity: 'HIGH',
          type: 'Persistent Attacker',
          count: attacker.count,
          description: `IP ${attacker.ip} shows persistent attack behavior`
        });
      }
    });

    // High error rates
    const errorCodes = ['403', '404', '500', '502'];
    const totalErrors = errorCodes.reduce((sum, code) => sum + (summary.statusCodeDistribution[code] || 0), 0);
    if (totalErrors > allResults.length * 0.3) {
      findings.push({
        severity: 'MEDIUM',
        type: 'High Error Rate',
        count: totalErrors,
        description: 'Unusually high number of HTTP errors detected'
      });
    }

    return findings;
  }

  buildReportPrompt(data) {
    return `
You are a cybersecurity analyst. Generate a comprehensive security analysis report in Markdown format based on the following log analysis data:

**Analysis Overview:**
- File: ${data.fileName}
- Dataset: ${data.datasetUrl}
- Analysis Date: ${new Date(data.analysisDate).toLocaleString()}
- Total Threats Detected: ${data.totalThreats}
- Unique Attackers: ${data.uniqueAttackers}
- Recent Activity (24h): ${data.recentAttacks} threats

**Attack Type Distribution:**
${data.topAttackTypes.map(([type, count]) => `- ${type}: ${count} incidents`).join('\n')}

**Top Attackers:**
${data.topAttackers.map((attacker) => `- ${attacker.ip}: ${attacker.count} attempts`).join('\n')}

**Most Targeted Paths:**
${data.topPaths.map(([path, count]) => `- ${path}: ${count} requests`).join('\n')}

**HTTP Methods:**
${data.methodCounts.map(([method, count]) => `- ${method}: ${count} requests`).join('\n')}

**Status Code Distribution:**
${Object.entries(data.statusCodeDistribution).map(([code, count]) => `- ${code}: ${count} responses`).join('\n')}

**Critical Findings:**
${data.criticalFindings.map((finding) => `- [${finding.severity}] ${finding.description} (${finding.count} incidents)`).join('\n')}

Please generate a professional security analysis report in Markdown format that includes:

1. **Executive Summary** - High-level overview of security posture and key findings
2. **Threat Landscape Analysis** - Detailed analysis of attack types and patterns
3. **Attacker Profile Analysis** - Analysis of attacker behavior and origins
4. **Vulnerability Assessment** - Most targeted areas and potential vulnerabilities
5. **Risk Assessment** - Risk levels and potential impact
6. **Recommendations** - Specific actionable security recommendations
7. **Incident Response** - Immediate actions needed
8. **Monitoring and Prevention** - Long-term security improvements

Use proper Markdown formatting with headers, bullet points, tables where appropriate, and emphasis for important findings. Be specific, professional, and actionable in your recommendations.
`;
  }

  canGenerateReport(config) {
    if (!config.providerId || !config.apiKey.trim()) {
      return false;
    }
    return true;
  }
}

export const reportGenerationService = new ReportGenerationService();
export { LLM_PROVIDERS };