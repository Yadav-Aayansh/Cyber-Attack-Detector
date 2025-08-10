export interface LLMProvider {
  id: string;
  name: string;
  description: string;
  requiresApiKey: boolean;
  customEndpoint?: boolean;
  defaultEndpoint?: string;
}

export interface LLMRequest {
  prompt: string;
  maxTokens?: number;
  temperature?: number;
}

export interface LLMResponse {
  text: string;
  usage?: {
    promptTokens?: number;
    completionTokens?: number;
    totalTokens?: number;
  };
}

export const LLM_PROVIDERS: LLMProvider[] = [
  {
    id: 'gemini',
    name: 'Google Gemini',
    description: 'Google\'s Gemini AI model',
    requiresApiKey: true,
  },
  {
    id: 'openai',
    name: 'OpenAI GPT',
    description: 'OpenAI\'s GPT models',
    requiresApiKey: true,
  },
  {
    id: 'anthropic',
    name: 'Anthropic Claude',
    description: 'Anthropic\'s Claude models',
    requiresApiKey: true,
  },
  {
    id: 'aipipe',
    name: 'AIPipe',
    description: 'AIPipe.org API service',
    requiresApiKey: true,
    customEndpoint: true,
    defaultEndpoint: 'https://aipipe.org/openrouter/v1/chat/completions',
  },
  {
    id: 'custom',
    name: 'Custom Endpoint',
    description: 'Custom OpenAI-compatible API endpoint',
    requiresApiKey: true,
    customEndpoint: true,
  },
];

export class LLMService {
  private async makeGeminiRequest(prompt: string, apiKey: string, options: LLMRequest): Promise<LLMResponse> {
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
          temperature: options.temperature || 0.7,
          topK: 40,
          topP: 0.95,
          maxOutputTokens: options.maxTokens || 2048,
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

    const data = await response.json();
    
    if (!data.candidates || data.candidates.length === 0) {
      throw new Error('No response from Gemini API');
    }

    return {
      text: data.candidates[0].content.parts[0].text,
      usage: data.usageMetadata ? {
        promptTokens: data.usageMetadata.promptTokenCount,
        completionTokens: data.usageMetadata.candidatesTokenCount,
        totalTokens: data.usageMetadata.totalTokenCount,
      } : undefined,
    };
  }

  private async makeOpenAIRequest(prompt: string, apiKey: string, options: LLMRequest, endpoint?: string): Promise<LLMResponse> {
    const baseUrl = endpoint || 'https://api.openai.com/v1';
    const response = await fetch(`${baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: 'gpt-3.5-turbo',
        messages: [
          {
            role: 'user',
            content: prompt
          }
        ],
        max_tokens: options.maxTokens || 2048,
        temperature: options.temperature || 0.7,
      })
    });

    if (!response.ok) {
      throw new Error(`OpenAI API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    
    if (!data.choices || data.choices.length === 0) {
      throw new Error('No response from OpenAI API');
    }

    return {
      text: data.choices[0].message.content,
      usage: data.usage ? {
        promptTokens: data.usage.prompt_tokens,
        completionTokens: data.usage.completion_tokens,
        totalTokens: data.usage.total_tokens,
      } : undefined,
    };
  }

  private async makeAnthropicRequest(prompt: string, apiKey: string, options: LLMRequest): Promise<LLMResponse> {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-3-sonnet-20240229',
        max_tokens: options.maxTokens || 2048,
        temperature: options.temperature || 0.7,
        messages: [
          {
            role: 'user',
            content: prompt
          }
        ]
      })
    });

    if (!response.ok) {
      throw new Error(`Anthropic API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    
    if (!data.content || data.content.length === 0) {
      throw new Error('No response from Anthropic API');
    }

    return {
      text: data.content[0].text,
      usage: data.usage ? {
        promptTokens: data.usage.input_tokens,
        completionTokens: data.usage.output_tokens,
        totalTokens: data.usage.input_tokens + data.usage.output_tokens,
      } : undefined,
    };
  }

  private async makeAIPipeRequest(prompt: string, apiKey: string, options: LLMRequest): Promise<LLMResponse> {
    // Use the correct AIPipe endpoint format
    const aipipeEndpoint = 'https://aipipe.org/openrouter/v1/chat/completions';
    
    const response = await fetch(aipipeEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: 'openai/gpt-4o-mini',
        messages: [
          {
            role: 'user',
            content: prompt
          }
        ],
        max_tokens: options.maxTokens || 2048,
        temperature: options.temperature || 0.7,
      })
    });

    if (!response.ok) {
      throw new Error(`AIPipe API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    
    // Handle different response formats
    let text = '';
    if (data.choices && data.choices.length > 0) {
      text = data.choices[0].message?.content || data.choices[0].text || '';
    } else if (data.response) {
      text = data.response;
    } else if (data.text) {
      text = data.text;
    } else {
      throw new Error('Unexpected response format from AIPipe API');
    }

    return {
      text,
      usage: data.usage ? {
        promptTokens: data.usage.prompt_tokens,
        completionTokens: data.usage.completion_tokens,
        totalTokens: data.usage.total_tokens,
      } : undefined,
    };
  }

  async generateResponse(
    providerId: string,
    prompt: string,
    apiKey: string,
    endpoint?: string,
    options: Partial<LLMRequest> = {}
  ): Promise<LLMResponse> {
    const requestOptions: LLMRequest = {
      prompt,
      maxTokens: options.maxTokens || 2048,
      temperature: options.temperature || 0.7,
    };

    switch (providerId) {
      case 'gemini':
        return this.makeGeminiRequest(prompt, apiKey, requestOptions);
      
      case 'openai':
        return this.makeOpenAIRequest(prompt, apiKey, requestOptions);
      
      case 'anthropic':
        return this.makeAnthropicRequest(prompt, apiKey, requestOptions);
      
      case 'aipipe':
        return this.makeAIPipeRequest(prompt, apiKey, requestOptions);
      
      case 'custom':
        if (!endpoint) {
          throw new Error('Custom endpoint URL is required');
        }
        return this.makeOpenAIRequest(prompt, apiKey, requestOptions, endpoint);
      
      default:
        throw new Error(`Unsupported LLM provider: ${providerId}`);
    }
  }
}

export const llmService = new LLMService();