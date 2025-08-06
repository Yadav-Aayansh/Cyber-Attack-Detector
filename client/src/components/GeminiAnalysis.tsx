import React from 'react';
import { Sparkles, Brain, Shield, AlertTriangle, CheckCircle, ExternalLink } from 'lucide-react';

interface GeminiAnalysisProps {
  analysis: string | null;
  isLoading: boolean;
  onAnalyze: () => void;
  hasApiKey: boolean;
}

export function GeminiAnalysis({ analysis, isLoading, onAnalyze, hasApiKey }: GeminiAnalysisProps) {
  const formatAnalysis = (text: string) => {
    // Split by common markdown headers and format
    const sections = text.split(/(?=##\s)/);
    
    return sections.map((section, index) => {
      if (!section.trim()) return null;
      
      const lines = section.trim().split('\n');
      const header = lines[0];
      const content = lines.slice(1).join('\n');
      
      if (header.startsWith('##')) {
        const title = header.replace(/^##\s*/, '');
        return (
          <div key={index} className="mb-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3 flex items-center">
              {title.toLowerCase().includes('recommendation') && <CheckCircle className="w-5 h-5 mr-2 text-green-500" />}
              {title.toLowerCase().includes('threat') && <AlertTriangle className="w-5 h-5 mr-2 text-red-500" />}
              {title.toLowerCase().includes('security') && <Shield className="w-5 h-5 mr-2 text-blue-500" />}
              {title}
            </h3>
            <div className="prose prose-sm dark:prose-invert max-w-none">
              {content.split('\n').map((line, lineIndex) => {
                if (line.trim().startsWith('- ')) {
                  return (
                    <li key={lineIndex} className="ml-4 mb-1 text-gray-700 dark:text-gray-300">
                      {line.replace(/^-\s*/, '')}
                    </li>
                  );
                } else if (line.trim().startsWith('* ')) {
                  return (
                    <li key={lineIndex} className="ml-4 mb-1 text-gray-700 dark:text-gray-300">
                      {line.replace(/^\*\s*/, '')}
                    </li>
                  );
                } else if (line.trim()) {
                  return (
                    <p key={lineIndex} className="mb-2 text-gray-700 dark:text-gray-300">
                      {line}
                    </p>
                  );
                }
                return null;
              })}
            </div>
          </div>
        );
      }
      
      return (
        <div key={index} className="mb-4">
          <p className="text-gray-700 dark:text-gray-300">{section}</p>
        </div>
      );
    });
  };

  return (
    <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-lg border border-gray-200 dark:border-gray-700">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-purple-100 dark:bg-purple-900/20 rounded-lg">
            <Brain className="w-6 h-6 text-purple-600 dark:text-purple-400" />
          </div>
          <div>
            <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
              AI Security Analysis
            </h2>
            <p className="text-sm text-gray-600 dark:text-gray-300">
              Powered by Google Gemini AI
            </p>
          </div>
        </div>
        
        <button
          onClick={onAnalyze}
          disabled={isLoading || !hasApiKey}
          className="flex items-center space-x-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors"
        >
          <Sparkles className="w-4 h-4" />
          <span>{isLoading ? 'Analyzing...' : 'Get AI Analysis'}</span>
        </button>
      </div>

      {!hasApiKey && (
        <div className="mb-6 p-4 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg">
          <div className="flex items-start space-x-3">
            <AlertTriangle className="w-5 h-5 text-yellow-600 dark:text-yellow-400 flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-sm text-yellow-800 dark:text-yellow-200 mb-2">
                <strong>Gemini API Key Required</strong>
              </p>
              <p className="text-sm text-yellow-700 dark:text-yellow-300 mb-3">
                To use AI analysis, you need a Google Gemini API key. Enter it in the field above.
              </p>
              <a
                href="https://makersuite.google.com/app/apikey"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center space-x-1 text-sm text-yellow-800 dark:text-yellow-200 hover:text-yellow-900 dark:hover:text-yellow-100 font-medium"
              >
                <span>Get your free API key</span>
                <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          </div>
        </div>
      )}

      {isLoading && (
        <div className="text-center py-8">
          <div className="w-8 h-8 border-4 border-purple-500 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
          <p className="text-gray-600 dark:text-gray-300">
            AI is analyzing your security threats...
          </p>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-2">
            This may take a few moments
          </p>
        </div>
      )}

      {analysis && !isLoading && (
        <div className="space-y-4">
          <div className="flex items-center space-x-2 mb-4">
            <CheckCircle className="w-5 h-5 text-green-500" />
            <span className="text-sm font-medium text-green-700 dark:text-green-300">
              Analysis Complete
            </span>
          </div>
          
          <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-6">
            <div className="space-y-4">
              {formatAnalysis(analysis)}
            </div>
          </div>
        </div>
      )}

      {!analysis && !isLoading && hasApiKey && (
        <div className="text-center py-8">
          <Brain className="w-16 h-16 text-gray-400 mx-auto mb-4" />
          <p className="text-xl text-gray-500 dark:text-gray-400 mb-2">Ready for AI Analysis</p>
          <p className="text-gray-400 dark:text-gray-500">
            Click "Get AI Analysis" to receive detailed security recommendations
          </p>
        </div>
      )}
    </div>
  );
}