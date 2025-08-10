import React, { useState } from 'react';
import { ChevronDown, Settings, Key, Globe, ExternalLink } from 'lucide-react';
import { LLM_PROVIDERS, LLMProvider } from '../services/llmProviders';

interface LLMProviderSelectorProps {
  selectedProvider: string;
  onProviderChange: (providerId: string) => void;
  apiKey: string;
  onApiKeyChange: (key: string) => void;
  customEndpoint: string;
  onCustomEndpointChange: (endpoint: string) => void;
}

export function LLMProviderSelector({
  selectedProvider,
  onProviderChange,
  apiKey,
  onApiKeyChange,
  customEndpoint,
  onCustomEndpointChange,
}: LLMProviderSelectorProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);

  const currentProvider = LLM_PROVIDERS.find(p => p.id === selectedProvider) || LLM_PROVIDERS[0];

  const getProviderLinks = (providerId: string) => {
    const links: { [key: string]: string } = {
      gemini: 'https://makersuite.google.com/app/apikey',
      openai: 'https://platform.openai.com/api-keys',
      anthropic: 'https://console.anthropic.com/account/keys',
      aipipe: 'https://aipipe.org/',
    };
    return links[providerId];
  };

  return (
    <div className="space-y-4">
      {/* Provider Selection */}
      <div className="relative">
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
          AI Provider
        </label>
        <button
          onClick={() => setIsOpen(!isOpen)}
          className="w-full flex items-center justify-between px-4 py-3 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent text-left"
        >
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 bg-purple-100 dark:bg-purple-900/20 rounded-lg flex items-center justify-center">
              <Settings className="w-4 h-4 text-purple-600 dark:text-purple-400" />
            </div>
            <div>
              <div className="font-medium text-gray-900 dark:text-white">
                {currentProvider.name}
              </div>
              <div className="text-sm text-gray-500 dark:text-gray-400">
                {currentProvider.description}
              </div>
            </div>
          </div>
          <ChevronDown className={`w-5 h-5 text-gray-400 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
        </button>

        {isOpen && (
          <div className="absolute z-10 w-full mt-1 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg shadow-lg max-h-60 overflow-y-auto">
            {LLM_PROVIDERS.map((provider) => (
              <button
                key={provider.id}
                onClick={() => {
                  onProviderChange(provider.id);
                  setIsOpen(false);
                }}
                className={`w-full px-4 py-3 text-left hover:bg-gray-50 dark:hover:bg-gray-600 flex items-center space-x-3 ${
                  selectedProvider === provider.id ? 'bg-purple-50 dark:bg-purple-900/20' : ''
                }`}
              >
                <div className="w-8 h-8 bg-purple-100 dark:bg-purple-900/20 rounded-lg flex items-center justify-center">
                  <Settings className="w-4 h-4 text-purple-600 dark:text-purple-400" />
                </div>
                <div className="flex-1">
                  <div className="font-medium text-gray-900 dark:text-white">
                    {provider.name}
                  </div>
                  <div className="text-sm text-gray-500 dark:text-gray-400">
                    {provider.description}
                  </div>
                </div>
                {selectedProvider === provider.id && (
                  <div className="w-2 h-2 bg-purple-600 rounded-full" />
                )}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* API Key Input */}
      {currentProvider.requiresApiKey && (
        <div>
          <div className="flex items-center justify-between mb-2">
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              API Key
            </label>
            {getProviderLinks(selectedProvider) && (
              <a
                href={getProviderLinks(selectedProvider)}
                target="_blank"
                rel="noopener noreferrer"
                className="text-sm text-purple-600 dark:text-purple-400 hover:text-purple-700 dark:hover:text-purple-300 flex items-center space-x-1"
              >
                <span>Get API Key</span>
                <ExternalLink className="w-3 h-3" />
              </a>
            )}
          </div>
          <div className="flex items-center space-x-3">
            <Key className="w-5 h-5 text-gray-400" />
            <input
              type="password"
              placeholder={`Enter your ${currentProvider.name} API key...`}
              value={apiKey}
              onChange={(e) => onApiKeyChange(e.target.value)}
              className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
            />
          </div>
        </div>
      )}

      {/* Custom Endpoint */}
      {currentProvider.customEndpoint && (
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
            API Endpoint
          </label>
          <div className="flex items-center space-x-3">
            <Globe className="w-5 h-5 text-gray-400" />
            <input
              type="url"
              placeholder={currentProvider.defaultEndpoint || 'https://api.example.com/v1/chat/completions'}
              value={customEndpoint}
              onChange={(e) => onCustomEndpointChange(e.target.value)}
              className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
            />
          </div>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
            {selectedProvider === 'aipipe' 
              ? 'AIPipe.org provides free AI API access without requiring an API key'
              : 'Enter the base URL for your OpenAI-compatible API endpoint'
            }
          </p>
        </div>
      )}

      {/* Advanced Settings Toggle */}
      <button
        onClick={() => setShowAdvanced(!showAdvanced)}
        className="text-sm text-purple-600 dark:text-purple-400 hover:text-purple-700 dark:hover:text-purple-300 flex items-center space-x-1"
      >
        <Settings className="w-4 h-4" />
        <span>{showAdvanced ? 'Hide' : 'Show'} Advanced Settings</span>
        <ChevronDown className={`w-4 h-4 transition-transform ${showAdvanced ? 'rotate-180' : ''}`} />
      </button>

      {/* Advanced Settings */}
      {showAdvanced && (
        <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Temperature (0.0 - 1.0)
            </label>
            <input
              type="range"
              min="0"
              max="1"
              step="0.1"
              defaultValue="0.7"
              className="w-full"
            />
            <div className="flex justify-between text-xs text-gray-500 dark:text-gray-400 mt-1">
              <span>More Focused</span>
              <span>More Creative</span>
            </div>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Max Tokens
            </label>
            <input
              type="number"
              min="100"
              max="4000"
              defaultValue="2048"
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
            />
          </div>
        </div>
      )}

      {/* Provider Info */}
      <div className="text-sm text-gray-500 dark:text-gray-400">
        <p>
          Your API key is stored locally and never sent to our servers. 
          {!currentProvider.requiresApiKey && selectedProvider === 'aipipe' && (
            <span className="text-green-600 dark:text-green-400 ml-1">
              No API key required for AIPipe.
            </span>
          )}
        </p>
      </div>
    </div>
  );
}