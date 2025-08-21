// Custom Threat Detection Service
import { llmService } from './llmService.js';

export class CustomThreatService {
  constructor() {
    this.customDetectors = this.loadCustomDetectors();
  }

  loadCustomDetectors() {
    try {
      const saved = localStorage.getItem('customThreatDetectors');
      return saved ? JSON.parse(saved) : {};
    } catch (error) {
      console.error('Failed to load custom detectors:', error);
      return {};
    }
  }

  saveCustomDetectors() {
    try {
      localStorage.setItem('customThreatDetectors', JSON.stringify(this.customDetectors));
    } catch (error) {
      console.error('Failed to save custom detectors:', error);
    }
  }

  async generateCustomDetector(threatName, description, config) {
    const prompt = this.buildDetectorPrompt(threatName, description);
    
    try {
      const response = await llmService.generateResponse(
        config.providerId,
        prompt,
        config.apiKey,
        config.customEndpoint,
        {
          temperature: 0.1,
          maxTokens: 2000,
        }
      );

      // Extract the function code from the response
      const functionCode = this.extractFunctionCode(response.text);
      
      // Create a unique ID for this detector
      const detectorId = this.generateDetectorId(threatName);
      
      // Store the custom detector
      const detector = {
        id: detectorId,
        name: threatName,
        description: description,
        code: functionCode,
        createdAt: new Date().toISOString(),
        severity: this.determineSeverity(threatName, description)
      };

      this.customDetectors[detectorId] = detector;
      this.saveCustomDetectors();

      return detector;
    } catch (error) {
      console.error('Failed to generate custom detector:', error);
      throw new Error(`Failed to generate detector: ${error.message}`);
    }
  }

  buildDetectorPrompt(threatName, description) {
    return `
You are a cybersecurity expert. Generate a JavaScript function to detect "${threatName}" threats in web server log entries.

Description: ${description}

The function should:
1. Take an array of log entries as parameter (each entry has: ip, timestamp, method, path, protocol, status, bytes, referrer, user_agent, host, server_ip)
2. Return an array of suspicious entries that match the threat pattern
3. Add a 'suspicion_reason' field to each suspicious entry explaining why it was flagged
4. Use appropriate regex patterns and logic to detect the threat
5. Be efficient and avoid false positives

Example log entry structure:
{
  ip: "192.168.1.100",
  timestamp: "2024-01-15T10:30:45.000Z",
  method: "GET",
  path: "/admin/login.php",
  protocol: "HTTP/1.1",
  status: "401",
  bytes: "1234",
  referrer: "https://example.com",
  user_agent: "Mozilla/5.0...",
  host: "example.com",
  server_ip: "10.0.0.1"
}

Generate ONLY the JavaScript function code without any markdown formatting or explanations. The function should be named 'detectCustomThreat' and follow this pattern:

function detectCustomThreat(entries) {
  // Your detection logic here
  const suspicious = entries.filter(entry => {
    // Detection conditions
  });
  
  return suspicious.map(entry => ({
    ...entry,
    suspicion_reason: 'Reason for flagging this entry'
  }));
}
`;
  }

  extractFunctionCode(response) {
    // Remove markdown code blocks if present
    let code = response.trim();
    code = code.replace(/^```javascript\s*\n?/i, '');
    code = code.replace(/^```\s*\n?/i, '');
    code = code.replace(/\n?```\s*$/i, '');
    
    // Ensure the function is properly formatted
    if (!code.includes('function detectCustomThreat')) {
      throw new Error('Generated code does not contain the required function');
    }
    
    return code.trim();
  }

  generateDetectorId(threatName) {
    return 'custom-' + threatName.toLowerCase()
      .replace(/[^a-z0-9\s]/g, '')
      .replace(/\s+/g, '-')
      .substring(0, 30) + '-' + Date.now();
  }

  determineSeverity(threatName, description) {
    const highSeverityKeywords = ['injection', 'exploit', 'attack', 'malware', 'breach', 'intrusion'];
    const mediumSeverityKeywords = ['probe', 'scan', 'suspicious', 'unauthorized', 'anomaly'];
    
    const text = (threatName + ' ' + description).toLowerCase();
    
    if (highSeverityKeywords.some(keyword => text.includes(keyword))) {
      return 'high';
    } else if (mediumSeverityKeywords.some(keyword => text.includes(keyword))) {
      return 'medium';
    }
    
    return 'low';
  }

  executeCustomDetector(detectorId, logData) {
    const detector = this.customDetectors[detectorId];
    if (!detector) {
      throw new Error('Custom detector not found');
    }

    try {
      // Create a safe execution context
      const func = new Function('entries', detector.code + '\nreturn detectCustomThreat(entries);');
      return func(logData);
    } catch (error) {
      console.error('Error executing custom detector:', error);
      throw new Error(`Failed to execute detector: ${error.message}`);
    }
  }

  deleteCustomDetector(detectorId) {
    if (this.customDetectors[detectorId]) {
      delete this.customDetectors[detectorId];
      this.saveCustomDetectors();
      return true;
    }
    return false;
  }

  getCustomDetectors() {
    return Object.values(this.customDetectors);
  }

  getCustomDetector(detectorId) {
    return this.customDetectors[detectorId];
  }
}

export const customThreatService = new CustomThreatService();