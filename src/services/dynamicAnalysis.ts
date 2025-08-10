import { llmService, LLM_PROVIDERS } from './llmProviders';
import { ParsedLogEntry } from '../utils/logParser';
import { ProcessedLogEntry, DynamicAnalysis } from '../types';

export interface DynamicAnalysisConfig {
  providerId: string;
  apiKey: string;
  customEndpoint?: string;
  temperature?: number;
  maxTokens?: number;
}

class DynamicAnalysisService {
  private analyses: Map<string, DynamicAnalysis> = new Map();

  async createAnalysis(description: string, config: DynamicAnalysisConfig): Promise<DynamicAnalysis> {
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

    const prompt = `
You are a cybersecurity expert. I need you to generate JavaScript code that analyzes web server log entries to detect specific security threats.

User Request: "${description}"

Please generate a JavaScript function that:
1. Takes an array of parsed log entries as input
2. Analyzes each entry to detect the specific threat described
3. Returns an array of suspicious entries with a suspicion_reason field

Each log entry has this structure:
{
  ip: string,
  timestamp: string,
  method: string,
  path: string,
  protocol: string,
  status: string,
  bytes: string,
  referrer: string,
  user_agent: string,
  host: string,
  server_ip: string
}

Requirements:
- Return ONLY the JavaScript function code, no explanations
- Function should be named 'detectThreats'
- Function should take 'entries' parameter (array of log entries)
- Return array of entries that match the threat pattern
- Add 'suspicion_reason' field to each returned entry explaining why it's suspicious
- Use regex patterns, string matching, and logical conditions as appropriate
- Be specific and accurate in detection logic
- Handle edge cases and avoid false positives

Example format:
function detectThreats(entries) {
  return entries.filter(entry => {
    // Your detection logic here
    if (/* condition */) {
      entry.suspicion_reason = "Reason for suspicion";
      return true;
    }
    return false;
  });
}
`;

    try {
      const response = await llmService.generateResponse(
        config.providerId,
        prompt,
        config.apiKey,
        config.customEndpoint,
        {
          temperature: config.temperature || 0.3, // Lower temperature for more consistent code generation
          maxTokens: config.maxTokens || 1024,
        }
      );

      // Extract the function code from the response
      let functionCode = response.text.trim();
      
      // Clean up the response - remove markdown code blocks if present
      functionCode = functionCode.replace(/```javascript\n?/g, '').replace(/```\n?/g, '');
      
      // Validate that we have a function
      if (!functionCode.includes('function detectThreats')) {
        throw new Error('Generated code does not contain the required detectThreats function');
      }

      // Create a unique ID for this analysis
      const id = `dynamic-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      
      // Generate a name from the description
      const name = this.generateAnalysisName(description);

      const analysis: DynamicAnalysis = {
        id,
        name,
        description,
        functionCode,
        createdAt: new Date().toISOString(),
      };

      // Store the analysis
      this.analyses.set(id, analysis);

      return analysis;
    } catch (error) {
      console.error('Dynamic analysis creation failed:', error);
      throw new Error(`Failed to create analysis: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async runAnalysis(analysisId: string, entries: ParsedLogEntry[]): Promise<ProcessedLogEntry[]> {
    const analysis = this.analyses.get(analysisId);
    if (!analysis) {
      throw new Error('Analysis not found');
    }

    try {
      // Create a safe execution environment
      const safeEval = new Function('entries', `
        ${analysis.functionCode}
        return detectThreats(entries);
      `);

      // Execute the generated function
      const results = safeEval(entries);

      // Validate results
      if (!Array.isArray(results)) {
        throw new Error('Analysis function must return an array');
      }

      // Convert to ProcessedLogEntry format
      return results.map(entry => ({
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
        suspicion_reason: entry.suspicion_reason || 'Custom analysis match',
        attack_type: analysis.name,
      }));
    } catch (error) {
      console.error('Analysis execution failed:', error);
      throw new Error(`Failed to execute analysis: ${error instanceof Error ? error.message : 'Execution error'}`);
    }
  }

  private generateAnalysisName(description: string): string {
    // Extract key terms and create a concise name
    const words = description.toLowerCase()
      .replace(/[^\w\s]/g, ' ')
      .split(/\s+/)
      .filter(word => word.length > 2)
      .filter(word => !['the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had', 'her', 'was', 'one', 'our', 'out', 'day', 'get', 'has', 'him', 'his', 'how', 'man', 'new', 'now', 'old', 'see', 'two', 'way', 'who', 'boy', 'did', 'its', 'let', 'put', 'say', 'she', 'too', 'use'].includes(word));

    // Take first few meaningful words and capitalize
    const nameWords = words.slice(0, 3).map(word => 
      word.charAt(0).toUpperCase() + word.slice(1)
    );

    return nameWords.join(' ') + ' Analysis';
  }

  canAnalyze(config: DynamicAnalysisConfig): boolean {
    const provider = LLM_PROVIDERS.find(p => p.id === config.providerId);
    if (!provider) return false;

    // Check if API key is required and provided
    if (provider.requiresApiKey && !config.apiKey.trim()) {
      return false;
    }

    // Check if custom endpoint is required and provided (except for aipipe)
    if (provider.customEndpoint && config.providerId === 'custom' && !config.customEndpoint?.trim()) {
      return false;
    }

    return true;
  }

  getAnalysis(id: string): DynamicAnalysis | undefined {
    return this.analyses.get(id);
  }

  getAllAnalyses(): DynamicAnalysis[] {
    return Array.from(this.analyses.values());
  }

  deleteAnalysis(id: string): boolean {
    return this.analyses.delete(id);
  }

  clear(): void {
    this.analyses.clear();
  }
}

export const dynamicAnalysisService = new DynamicAnalysisService();