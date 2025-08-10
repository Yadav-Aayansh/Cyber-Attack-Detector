import React, { useState } from 'react';
import { Sparkles, Brain, Settings, Plus, Wand2 } from 'lucide-react';
import { LLMProviderSelector } from './LLMProviderSelector';

interface DynamicAnalysisCardProps {
  onCreateAnalysis: (description: string) => void;
  isCreating: boolean;
  selectedProvider: string;
  onProviderChange: (providerId: string) => void;
  apiKey: string;
  onApiKeyChange: (key: string) => void;
  customEndpoint: string;
  onCustomEndpointChange: (endpoint: string) => void;
  canAnalyze: boolean;
}

export function DynamicAnalysisCard({
  onCreateAnalysis,
  isCreating,
  selectedProvider,
  onProviderChange,
  apiKey,
  onApiKeyChange,
  customEndpoint,
  onCustomEndpointChange,
  canAnalyze,
}: DynamicAnalysisCardProps) {
  const [description, setDescription] = useState('');
  const [showConfig, setShowConfig] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (description.trim() && canAnalyze) {
      onCreateAnalysis(description.trim());
      setDescription('');
    }
  };

  const examplePrompts = [
    "Look for password or secret extraction attacks",
    "Detect attempts to access configuration files",
    "Find suspicious file upload attempts",
    "Identify potential data exfiltration patterns",
    "Detect API abuse or rate limiting violations",
    "Find attempts to access backup files",
  ];

  return (
    <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-lg border border-gray-200 dark:border-gray-700">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-purple-100 dark:bg-purple-900/20 rounded-lg">
            <Wand2 className="w-6 h-6 text-purple-600 dark:text-purple-400" />
          </div>
          <div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              AI-Powered Custom Analysis
            </h3>
            <p className="text-sm text-gray-600 dark:text-gray-300">
              Describe what you want to analyze and AI will create the detection logic
            </p>
          </div>
        </div>
        
        <button
          onClick={() => setShowConfig(!showConfig)}
          className="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
        >
          <Settings className="w-5 h-5" />
        </button>
      </div>

      {/* Configuration Panel */}
      {showConfig && (
        <div className="mb-6 p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
          <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-3">AI Provider Configuration</h4>
          <LLMProviderSelector
            selectedProvider={selectedProvider}
            onProviderChange={onProviderChange}
            apiKey={apiKey}
            onApiKeyChange={onApiKeyChange}
            customEndpoint={customEndpoint}
            onCustomEndpointChange={onCustomEndpointChange}
          />
        </div>
      )}

      {/* Analysis Input Form */}
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
            Describe the analysis you want to perform
          </label>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="e.g., Look for password or secret extraction attacks, Find attempts to access sensitive configuration files..."
            className="w-full px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-white resize-none"
            rows={3}
            disabled={isCreating}
          />
        </div>

        <button
          type="submit"
          disabled={!description.trim() || isCreating || !canAnalyze}
          className="w-full flex items-center justify-center space-x-2 px-4 py-3 bg-purple-600 hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors"
        >
          {isCreating ? (
            <>
              <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
              <span>Creating Analysis...</span>
            </>
          ) : (
            <>
              <Plus className="w-5 h-5" />
              <span>Create Custom Analysis</span>
            </>
          )}
        </button>
      </form>

      {/* Example Prompts */}
      <div className="mt-6">
        <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">Example Analysis Ideas:</h4>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          {examplePrompts.map((prompt, index) => (
            <button
              key={index}
              onClick={() => setDescription(prompt)}
              disabled={isCreating}
              className="text-left p-3 text-sm bg-gray-50 dark:bg-gray-700 hover:bg-gray-100 dark:hover:bg-gray-600 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <div className="flex items-start space-x-2">
                <Sparkles className="w-4 h-4 text-purple-500 mt-0.5 flex-shrink-0" />
                <span className="text-gray-700 dark:text-gray-300">{prompt}</span>
              </div>
            </button>
          ))}
        </div>
      </div>

      {!canAnalyze && (
        <div className="mt-4 p-3 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg">
          <div className="flex items-center space-x-2">
            <Brain className="w-5 h-5 text-yellow-600 dark:text-yellow-400" />
            <p className="text-sm text-yellow-800 dark:text-yellow-200">
              Please configure your AI provider settings to create custom analyses
            </p>
          </div>
        </div>
      )}
    </div>
  );
}