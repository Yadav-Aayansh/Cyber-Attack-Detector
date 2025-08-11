import { ProcessedLogEntry } from '../types';
import { llmService, LLM_PROVIDERS } from './llmProviders';

export interface AIAnalysisConfig {
  providerId: string;
  apiKey: string;
  customEndpoint?: string;
  temperature?: number;
  maxTokens?: number;
}

class AIAnalysisService {
  async analyzeSecurityThreats(threats: ProcessedLogEntry[], config: AIAnalysisConfig): Promise<string> {
    // Validate configuration
    const provider = LLM_PROVIDERS.find(p => p.id === config.providerId);
    if (!provider) {
      throw new Error(`Unknown provider: ${config.providerId}`);
    }

    if (provider.requiresApiKey && !config.apiKey.trim()) {
      throw new Error(`API key is required for ${provider.name}`);
    }

    if (provider.customEndpoint && config.providerId !== 'aipipe' && !config.customEndpoint?.trim()) {
      throw new Error(`Custom endpoint is required for ${provider.name}`);
    }

    // Prepare threat summary for analysis
    const threatSummary = this.prepareThreatSummary(threats);
    
    const prompt = `
As a cybersecurity expert, analyze the following security threats detected in web server logs and provide comprehensive recommendations. Don't use bold formatting (**):

${threatSummary}

Please provide a detailed analysis including:

## Threat Assessment
- What is the overall risk level?  
- What are the most critical threats identified?  
- What is the potential impact on the system?

## Immediate Security Actions
- What urgent steps must be taken right now?  
- What emergency response measures are needed?  
- What immediate patches or fixes are required?

## Long-Term Recommendations
- What security improvements should be made long-term?  
- What configuration changes are necessary?  
- What tools or frameworks should be implemented?

Please be specific and actionable in your recommendations. Focus on practical steps that can be implemented immediately.
    `;

    try {
      const response = await llmService.generateResponse(
        config.providerId,
        prompt,
        config.apiKey,
        config.customEndpoint,
        {
          temperature: config.temperature || 0.7,
          maxTokens: config.maxTokens || 2048,
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
      
      return cleanedText;
    } catch (error) {
      console.error('AI Analysis failed:', error);
      throw new Error(`Failed to get AI analysis: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private prepareThreatSummary(threats: ProcessedLogEntry[]): string {
    // Group threats by type
    const threatsByType: Record<string, ProcessedLogEntry[]> = {};
    const ipCounts: Record<string, number> = {};
    const pathCounts: Record<string, number> = {};

    threats.forEach(threat => {
      // Group by attack type
      if (!threatsByType[threat.attack_type]) {
        threatsByType[threat.attack_type] = [];
      }
      threatsByType[threat.attack_type].push(threat);

      // Count IPs
      ipCounts[threat.ip] = (ipCounts[threat.ip] || 0) + 1;

      // Count paths
      pathCounts[threat.path] = (pathCounts[threat.path] || 0) + 1;
    });

    // Get top attackers
    const topAttackers = Object.entries(ipCounts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 10);

    // Get most targeted paths
    const topPaths = Object.entries(pathCounts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 10);

    let summary = `SECURITY THREAT ANALYSIS REPORT\n\n`;
    summary += `Total Threats Detected: ${threats.length}\n`;
    summary += `Unique Attack Types: ${Object.keys(threatsByType).length}\n`;
    summary += `Unique Attacking IPs: ${Object.keys(ipCounts).length}\n\n`;

    // Attack types breakdown
    summary += `ATTACK TYPES DETECTED:\n`;
    Object.entries(threatsByType).forEach(([type, typeThreats]) => {
      summary += `- ${type}: ${typeThreats.length} attempts\n`;
      
      // Show sample suspicious reasons for this attack type
      const reasons = [...new Set(typeThreats.map(t => t.suspicion_reason).filter(r => r))];
      if (reasons.length > 0) {
        summary += `  Sample patterns: ${reasons.slice(0, 3).join(', ')}\n`;
      }
    });

    summary += `\nTOP ATTACKING IPs:\n`;
    topAttackers.forEach(([ip, count], index) => {
      summary += `${index + 1}. ${ip}: ${count} attempts\n`;
    });

    summary += `\nMOST TARGETED PATHS:\n`;
    topPaths.forEach(([path, count], index) => {
      summary += `${index + 1}. ${path}: ${count} attempts\n`;
    });

    // Add sample threat details
    summary += `\nSAMPLE THREAT DETAILS:\n`;
    Object.entries(threatsByType).forEach(([type, typeThreats]) => {
      const sample = typeThreats[0];
      summary += `\n${type} Example:\n`;
      summary += `- IP: ${sample.ip}\n`;
      summary += `- Path: ${sample.path}\n`;
      summary += `- Method: ${sample.method}\n`;
      summary += `- Status: ${sample.status}\n`;
      summary += `- User Agent: ${sample.user_agent.substring(0, 100)}...\n`;
      if (sample.suspicion_reason) {
        summary += `- Reason: ${sample.suspicion_reason}\n`;
      }
    });

    return summary;
  }

  canAnalyze(config: AIAnalysisConfig): boolean {
    const provider = LLM_PROVIDERS.find(p => p.id === config.providerId);
    if (!provider) return false;

    // Check if API key is required and provided
    if (provider.requiresApiKey && !config.apiKey.trim()) {
      return false;
    }

    // Check if custom endpoint is required and provided (except for aipipe)
    if (provider.customEndpoint && config.providerId !== 'aipipe' && !config.customEndpoint?.trim()) {
      return false;
    }

    return true;
  }
}

export const aiAnalysisService = new AIAnalysisService();