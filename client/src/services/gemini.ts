import { ProcessedLogEntry } from '../types';

interface GeminiResponse {
  candidates: Array<{
    content: {
      parts: Array<{
        text: string;
      }>;
    };
  }>;
}

class GeminiService {
  private async makeRequest(prompt: string, apiKey: string): Promise<string> {
    const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        contents: [{
          parts: [{
            text: prompt
          }]
        }],
        generationConfig: {
          temperature: 0.7,
          topK: 40,
          topP: 0.95,
          maxOutputTokens: 2048,
        },
        safetySettings: [
          {
            category: "HARM_CATEGORY_HARASSMENT",
            threshold: "BLOCK_MEDIUM_AND_ABOVE"
          },
          {
            category: "HARM_CATEGORY_HATE_SPEECH",
            threshold: "BLOCK_MEDIUM_AND_ABOVE"
          },
          {
            category: "HARM_CATEGORY_SEXUALLY_EXPLICIT",
            threshold: "BLOCK_MEDIUM_AND_ABOVE"
          },
          {
            category: "HARM_CATEGORY_DANGEROUS_CONTENT",
            threshold: "BLOCK_MEDIUM_AND_ABOVE"
          }
        ]
      })
    });

    if (!response.ok) {
      throw new Error(`Gemini API error: ${response.status} ${response.statusText}`);
    }

    const data: GeminiResponse = await response.json();
    
    if (!data.candidates || data.candidates.length === 0) {
      throw new Error('No response from Gemini API');
    }

    return data.candidates[0].content.parts[0].text;
  }

  async analyzeSecurityThreats(threats: ProcessedLogEntry[], apiKey: string): Promise<string> {
    // Prepare threat summary for analysis
    const threatSummary = this.prepareThreatSummary(threats);
    
    const prompt = `
As a cybersecurity expert, analyze the following security threats detected in web server logs and provide comprehensive recommendations, Don't use bold char (**):

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

    return this.makeRequest(prompt, apiKey);
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
}

export const geminiService = new GeminiService();