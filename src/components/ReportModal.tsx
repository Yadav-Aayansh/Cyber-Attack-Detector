import React, { useState } from 'react';
import { X, FileBarChart, Download, Copy, Check, Settings, Sparkles } from 'lucide-react';
import { marked } from 'marked';
import { LLMProviderSelector } from './LLMProviderSelector';

interface ReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  onGenerateReport: (config: {
    providerId: string;
    apiKey: string;
    customEndpoint?: string;
  }) => void;
  isGenerating: boolean;
  reportMarkdown: string;
  selectedProvider: string;
  onProviderChange: (providerId: string) => void;
  apiKey: string;
  onApiKeyChange: (key: string) => void;
  customEndpoint: string;
  onCustomEndpointChange: (endpoint: string) => void;
  canGenerate: boolean;
}

export function ReportModal({
  isOpen,
  onClose,
  onGenerateReport,
  isGenerating,
  reportMarkdown,
  selectedProvider,
  onProviderChange,
  apiKey,
  onApiKeyChange,
  customEndpoint,
  onCustomEndpointChange,
  canGenerate,
}: ReportModalProps) {
  const [showConfig, setShowConfig] = useState(false);
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<'preview' | 'markdown'>('preview');

  if (!isOpen) return null;

  const handleGenerateReport = () => {
    onGenerateReport({
      providerId: selectedProvider,
      apiKey,
      customEndpoint,
    });
  };

  const handleCopyMarkdown = async () => {
    try {
      await navigator.clipboard.writeText(reportMarkdown);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (error) {
      console.error('Failed to copy to clipboard:', error);
    }
  };

  const handleDownloadMarkdown = () => {
    const blob = new Blob([reportMarkdown], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `security-report-${new Date().toISOString().split('T')[0]}.md`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleDownloadHTML = () => {
    const htmlContent = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
            background: #fff;
        }
        h1 { color: #1a202c; border-bottom: 3px solid #3182ce; padding-bottom: 0.5rem; }
        h2 { color: #2d3748; border-bottom: 2px solid #e2e8f0; padding-bottom: 0.5rem; margin-top: 2rem; }
        h3 { color: #4a5568; margin-top: 1.5rem; }
        table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
        th, td { border: 1px solid #e2e8f0; padding: 0.75rem; text-align: left; }
        th { background: #f7fafc; font-weight: 600; }
        code { background: #f1f5f9; padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-family: 'Monaco', 'Consolas', monospace; }
        pre { background: #1a202c; color: #e2e8f0; padding: 1rem; border-radius: 0.5rem; overflow-x: auto; }
        blockquote { border-left: 4px solid #3182ce; padding-left: 1rem; margin: 1rem 0; background: #f8fafc; }
        .severity-high { color: #e53e3e; background: #fed7d7; padding: 0.25rem 0.5rem; border-radius: 0.25rem; }
        .severity-medium { color: #dd6b20; background: #feebc8; padding: 0.25rem 0.5rem; border-radius: 0.25rem; }
        .severity-low { color: #38a169; background: #c6f6d5; padding: 0.25rem 0.5rem; border-radius: 0.25rem; }
        @media print {
            body { padding: 1rem; }
            h1, h2 { page-break-after: avoid; }
        }
    </style>
</head>
<body>
    ${marked(reportMarkdown)}
</body>
</html>`;

    const blob = new Blob([htmlContent], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `security-report-${new Date().toISOString().split('T')[0]}.html`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-2xl w-full max-w-6xl max-h-[90vh] overflow-hidden animate-scale-in">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-purple-100 dark:bg-purple-900/20 rounded-lg">
              <FileBarChart className="w-6 h-6 text-purple-600 dark:text-purple-400" />
            </div>
            <div>
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
                Security Analysis Report
              </h2>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                AI-powered comprehensive security assessment
              </p>
            </div>
          </div>
          
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setShowConfig(!showConfig)}
              className="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
            >
              <Settings className="w-5 h-5" />
            </button>
            <button
              onClick={onClose}
              className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Configuration Panel */}
        {showConfig && (
          <div className="p-6 bg-gray-50 dark:bg-gray-700 border-b border-gray-200 dark:border-gray-600">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">AI Provider Configuration</h3>
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

        {/* Content */}
        <div className="flex-1 flex flex-col min-h-0">
          {!reportMarkdown ? (
            /* Generation Interface */
            <div className="p-8 text-center">
              <div className="max-w-md mx-auto">
                <div className="p-4 bg-purple-100 dark:bg-purple-900/20 rounded-full w-20 h-20 mx-auto mb-6 flex items-center justify-center">
                  <Sparkles className="w-10 h-10 text-purple-600 dark:text-purple-400" />
                </div>
                
                <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-4">
                  Generate AI Security Report
                </h3>
                
                <p className="text-gray-600 dark:text-gray-300 mb-8">
                  Create a comprehensive security analysis report with AI-powered insights, 
                  recommendations, and actionable security measures based on your log analysis results.
                </p>

                {!canGenerate && (
                  <div className="mb-6 p-4 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg">
                    <p className="text-sm text-yellow-800 dark:text-yellow-200">
                      Please configure your AI provider settings above to generate reports.
                    </p>
                  </div>
                )}

                <button
                  onClick={handleGenerateReport}
                  disabled={isGenerating || !canGenerate}
                  className="flex items-center justify-center space-x-2 px-8 py-3 bg-purple-600 hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors mx-auto"
                >
                  {isGenerating ? (
                    <>
                      <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                      <span>Generating Report...</span>
                    </>
                  ) : (
                    <>
                      <FileBarChart className="w-5 h-5" />
                      <span>Generate Security Report</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          ) : (
            /* Report Display */
            <div className="flex flex-col h-full">
              {/* Tab Navigation */}
              <div className="flex items-center justify-between px-6 py-3 border-b border-gray-200 dark:border-gray-700">
                <div className="flex space-x-1">
                  <button
                    onClick={() => setActiveTab('preview')}
                    className={`px-4 py-2 text-sm font-medium rounded-lg transition-colors ${
                      activeTab === 'preview'
                        ? 'bg-purple-100 dark:bg-purple-900/20 text-purple-700 dark:text-purple-300'
                        : 'text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200'
                    }`}
                  >
                    Preview
                  </button>
                  <button
                    onClick={() => setActiveTab('markdown')}
                    className={`px-4 py-2 text-sm font-medium rounded-lg transition-colors ${
                      activeTab === 'markdown'
                        ? 'bg-purple-100 dark:bg-purple-900/20 text-purple-700 dark:text-purple-300'
                        : 'text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200'
                    }`}
                  >
                    Markdown
                  </button>
                </div>

                {/* Action Buttons */}
                <div className="flex items-center space-x-2">
                  <button
                    onClick={handleCopyMarkdown}
                    className="flex items-center space-x-1 px-3 py-1 text-sm bg-gray-600 hover:bg-gray-700 text-white rounded-lg transition-colors"
                  >
                    {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                    <span>{copied ? 'Copied!' : 'Copy'}</span>
                  </button>
                  <button
                    onClick={handleDownloadMarkdown}
                    className="flex items-center space-x-1 px-3 py-1 text-sm bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
                  >
                    <Download className="w-4 h-4" />
                    <span>MD</span>
                  </button>
                  <button
                    onClick={handleDownloadHTML}
                    className="flex items-center space-x-1 px-3 py-1 text-sm bg-green-600 hover:bg-green-700 text-white rounded-lg transition-colors"
                  >
                    <Download className="w-4 h-4" />
                    <span>HTML</span>
                  </button>
                </div>
              </div>

              {/* Report Content */}
              <div className="flex-1 overflow-y-auto premium-scrollbar min-h-0 max-h-[calc(90vh-300px)]">
                {activeTab === 'preview' ? (
                  <div 
                    className="p-6 prose prose-lg max-w-none dark:prose-invert"
                    dangerouslySetInnerHTML={{ 
                      __html: marked(reportMarkdown, {
                        breaks: true,
                        gfm: true,
                        headerIds: true,
                        mangle: true,
                      })
                    }}
                  />
                ) : (
                  <div className="p-6 h-full">
                    <pre className="bg-gray-900 dark:bg-gray-950 text-gray-100 p-4 rounded-lg overflow-x-auto text-sm font-mono whitespace-pre-wrap border border-gray-700">
                      {reportMarkdown}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}