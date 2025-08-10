import React, { useState, useMemo } from 'react';
import { Shield, Moon, Sun, Key, Download, BarChart3, Database, FileText, Sparkles } from 'lucide-react';

// Components
import { FileUpload } from './components/FileUpload';
import { AttackTypeCard } from './components/AttackTypeCard';
import { Dashboard } from './components/Dashboard';
import { DataTable } from './components/DataTable';
import { FacetedDataTable } from './components/FacetedDataTable';
import { AIAnalysis } from './components/AIAnalysis';
import { Modal } from './components/Modal';
import { Toast } from './components/Toast';

// Hooks and utilities
import { useTheme } from './hooks/useTheme';
import { useToast } from './hooks/useToast';
import { processLogData, exportToCSV, exportToJSON, downloadFile } from './utils/dataProcessing';

// Services and config
import { apiService } from './services/api';
import { clientAnalysisService } from './services/clientSideAnalysis';
import { aiAnalysisService } from './services/aiAnalysis';
import { ATTACK_TYPES } from './config/attackTypes';

// Types
import { ProcessedLogEntry, Filters, AnalysisSummary, AttackTypeConfig } from './types';

function App() {
  const { theme, toggleTheme } = useTheme();
  const { toasts, addToast, removeToast } = useToast();

  // State management
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [allResults, setAllResults] = useState<ProcessedLogEntry[]>([]);
  const [scanResults, setScanResults] = useState<Record<string, ProcessedLogEntry[]>>({});
  const [isScanning, setIsScanning] = useState<Record<string, boolean>>({});
  
  // AI Analysis state
  const [selectedProvider, setSelectedProvider] = useState('gemini');
  const [apiKey, setApiKey] = useState('');
  const [customEndpoint, setCustomEndpoint] = useState('');
  const [aiAnalysis, setAiAnalysis] = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  
  const [activeView, setActiveView] = useState<'overview' | 'dashboard' | 'data' | 'analysis'>('overview');
  const [selectedAttackType, setSelectedAttackType] = useState<string | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);

  // Filters
  const [filters, setFilters] = useState<Filters>({
    attackType: '',
    statusCode: '',
    ip: '',
    dateRange: '',
    severity: '',
    search: '',
    method: '',
  });

  // Computed values
  const summary: AnalysisSummary = useMemo(() => {
    const attackTypeCounts: Record<string, number> = {};
    const ipCounts: Record<string, number> = {};
    const statusCounts: Record<string, number> = {};
    const timelineCounts: Record<string, number> = {};

    allResults.forEach(entry => {
      // Attack type counts
      attackTypeCounts[entry.attack_type] = (attackTypeCounts[entry.attack_type] || 0) + 1;
      
      // IP counts
      ipCounts[entry.ip] = (ipCounts[entry.ip] || 0) + 1;
      
      // Status code counts
      statusCounts[entry.status.toString()] = (statusCounts[entry.status.toString()] || 0) + 1;
      
      // Timeline data (by date)
      const date = new Date(entry.timestamp).toDateString();
      timelineCounts[date] = (timelineCounts[date] || 0) + 1;
    });

    const topAttackers = Object.entries(ipCounts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 20)
      .map(([ip, count]) => ({ ip, count }));

    const timelineData = Object.entries(timelineCounts)
      .sort(([a], [b]) => new Date(a).getTime() - new Date(b).getTime())
      .map(([date, count]) => ({ date, count }));

    return {
      totalThreats: allResults.length,
      attackTypeCounts,
      topAttackers,
      statusCodeDistribution: statusCounts,
      timelineData,
    };
  }, [allResults]);

  // Handlers
  const handleFileSelect = (file: File) => {
    setSelectedFile(file);
    setAllResults([]);
    setScanResults({});
    setAiAnalysis(null);
    // Clear any previous analysis data
    clientAnalysisService.clear();
    addToast(`File "${file.name}" selected successfully`, 'success');
  };

  const handleScan = async (attackType: AttackTypeConfig) => {
    if (!selectedFile) {
      addToast('Please select a log file first', 'error');
      return;
    }

    setIsScanning(prev => ({ ...prev, [attackType.name]: true }));

    try {
      const response = await apiService.scanLogs(attackType.endpoint, {
        file: selectedFile,
      });

      const processedData = processLogData(response.results, attackType.name);
      
      setScanResults(prev => ({
        ...prev,
        [attackType.name]: processedData,
      }));

      // Update all results
      setAllResults(prev => {
        const filtered = prev.filter(entry => entry.attack_type !== attackType.name);
        return [...filtered, ...processedData];
      });

      addToast(`${attackType.name} scan completed: ${processedData.length} threats found`, 'success');
    } catch (error) {
      console.error('Scan failed:', error);
      addToast(`Failed to scan for ${attackType.name}`, 'error');
    } finally {
      setIsScanning(prev => ({ ...prev, [attackType.name]: false }));
    }
  };

  const handleRunAll = async () => {
    if (!selectedFile) {
      addToast('Please select a log file first', 'error');
      return;
    }

    addToast('Starting comprehensive security scan...', 'info');
    
    // Clear previous results
    setAllResults([]);
    setScanResults({});

    let totalThreats = 0;
    let completedScans = 0;

    // Run scans sequentially to avoid overwhelming the system
    for (const attackType of ATTACK_TYPES) {
      try {
        setIsScanning(prev => ({ ...prev, [attackType.name]: true }));
        
        const response = await apiService.scanLogs(attackType.endpoint, {
          file: selectedFile,
        });

        const processedData = processLogData(response.results, attackType.name);
        totalThreats += processedData.length;
        completedScans++;
        
        setScanResults(prev => ({
          ...prev,
          [attackType.name]: processedData,
        }));

        // Update all results
        setAllResults(prev => [...prev, ...processedData]);

        // Show progress
        addToast(`${attackType.name}: ${processedData.length} threats found (${completedScans}/${ATTACK_TYPES.length})`, 'success');
        
      } catch (error) {
        console.error(`Scan failed for ${attackType.name}:`, error);
        addToast(`Failed to scan for ${attackType.name}`, 'error');
        completedScans++;
      } finally {
        setIsScanning(prev => ({ ...prev, [attackType.name]: false }));
      }
    }

    // Final summary
    addToast(`Comprehensive scan completed! Found ${totalThreats} total threats across ${completedScans} attack types`, 'success');
  };

  const handleViewDetails = (attackType: string) => {
    setSelectedAttackType(attackType);
    setIsModalOpen(true);
  };

  const handleAiAnalysis = async () => {
    const config = {
      providerId: selectedProvider,
      apiKey,
      customEndpoint,
    };

    if (!aiAnalysisService.canAnalyze(config)) {
      addToast('Please configure your AI provider settings', 'error');
      return;
    }

    if (allResults.length === 0) {
      addToast('No threat data available for analysis', 'error');
      return;
    }

    setIsAnalyzing(true);

    try {
      const analysis = await aiAnalysisService.analyzeSecurityThreats(allResults, config);
      setAiAnalysis(analysis);
      addToast('AI analysis completed successfully', 'success');
    } catch (error) {
      console.error('AI analysis failed:', error);
      addToast(`Failed to get AI analysis: ${error instanceof Error ? error.message : 'Unknown error'}`, 'error');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleExport = (format: 'csv' | 'json') => {
    if (allResults.length === 0) {
      addToast('No data to export', 'error');
      return;
    }

    try {
      const timestamp = new Date().toISOString().split('T')[0];
      const filename = `log-analysis-${timestamp}.${format}`;
      
      if (format === 'csv') {
        const csvContent = exportToCSV(allResults);
        downloadFile(csvContent, filename, 'text/csv');
      } else {
        const jsonContent = exportToJSON(allResults);
        downloadFile(jsonContent, filename, 'application/json');
      }
      
      addToast(`Data exported as ${format.toUpperCase()}`, 'success');
    } catch (error) {
      addToast('Failed to export data', 'error');
    }
  };

  const getAttackTypeCount = (attackType: string): number => {
    return scanResults[attackType]?.length || 0;
  };

  const hasResults = (attackType: string): boolean => {
    return (scanResults[attackType]?.length || 0) > 0;
  };

  const modalData = selectedAttackType ? scanResults[selectedAttackType] || [] : [];

  return (
    <div className={`min-h-screen transition-colors duration-200 ${
      theme === 'dark' ? 'dark bg-gray-900' : 'bg-gray-50'
    }`}>
      {/* Header */}
      <header className="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-blue-100 dark:bg-blue-900/20 rounded-lg">
                <Shield className="w-8 h-8 text-blue-600 dark:text-blue-400" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-gray-900 dark:text-white">
                  Cyber Attack Detector
                </h1>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  Advanced Security Log Analysis
                </p>
              </div>
            </div>

            <div className="flex items-center space-x-4">
              {/* Export Buttons */}
              {allResults.length > 0 && (
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => handleExport('csv')}
                    className="flex items-center space-x-1 px-3 py-1 text-sm bg-green-600 hover:bg-green-700 text-white rounded-lg transition-colors"
                  >
                    <Download className="w-4 h-4" />
                    <span>CSV</span>
                  </button>
                  <button
                    onClick={() => handleExport('json')}
                    className="flex items-center space-x-1 px-3 py-1 text-sm bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
                  >
                    <Download className="w-4 h-4" />
                    <span>JSON</span>
                  </button>
                </div>
              )}

              {/* Theme Toggle */}
              <button
                onClick={toggleTheme}
                className="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
              >
                {theme === 'light' ? <Moon className="w-5 h-5" /> : <Sun className="w-5 h-5" />}
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Navigation */}
      <nav className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex space-x-8">
            {[
              { id: 'overview', label: 'Overview', icon: Shield },
              { id: 'dashboard', label: 'Dashboard', icon: BarChart3 },
              { id: 'data', label: 'Data Table', icon: Database },
              { id: 'analysis', label: 'AI Analysis', icon: Sparkles },
            ].map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                onClick={() => setActiveView(id as any)}
                className={`flex items-center space-x-2 px-3 py-4 text-sm font-medium border-b-2 transition-colors ${
                  activeView === id
                    ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                    : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span>{label}</span>
              </button>
            ))}
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeView === 'overview' && (
          <div className="space-y-8">
            {/* File Upload */}
            <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-lg">
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-4">
                Upload Log File
              </h2>
              <FileUpload
                onFileSelect={handleFileSelect}
                acceptedTypes={['.log', '.txt', '*/*']}
                maxSize={100 * 1024 * 1024} // 100MB
              />
              {selectedFile && (
                <div className="mt-4 p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                  <p className="text-sm text-blue-800 dark:text-blue-200">
                    <FileText className="w-4 h-4 inline mr-2" />
                    Selected: {selectedFile.name} ({(selectedFile.size / 1024 / 1024).toFixed(2)} MB)
                  </p>
                </div>
              )}
            </div>

            {/* Attack Type Cards */}
            {selectedFile && (
              <div>
                <div className="flex items-center justify-between mb-6">
                  <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
                    Security Threat Analysis
                  </h2>
                  <button
                    onClick={handleRunAll}
                    disabled={Object.values(isScanning).some(Boolean)}
                    className="flex items-center space-x-2 px-6 py-3 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-all duration-200 shadow-lg hover:shadow-xl transform hover:-translate-y-0.5"
                  >
                    {Object.values(isScanning).some(Boolean) ? (
                      <>
                        <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                        <span>Running Scans...</span>
                      </>
                    ) : (
                      <>
                        <Shield className="w-5 h-5" />
                        <span>Run All Scans</span>
                      </>
                    )}
                  </button>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
                  {ATTACK_TYPES.map((attackType) => (
                    <AttackTypeCard
                      key={attackType.name}
                      config={attackType}
                      count={getAttackTypeCount(attackType.name)}
                      isLoading={isScanning[attackType.name]}
                      onScan={() => handleScan(attackType)}
                      onViewDetails={() => handleViewDetails(attackType.name)}
                      hasResults={hasResults(attackType.name)}
                    />
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {activeView === 'dashboard' && (
          <Dashboard
            data={allResults}
            summary={summary}
            isLoading={Object.values(isScanning).some(Boolean)}
          />
        )}

        {activeView === 'data' && (
          <DataTable
            data={allResults}
            isLoading={Object.values(isScanning).some(Boolean)}
            filters={filters}
            onFiltersChange={setFilters}
          />
        )}

        {activeView === 'analysis' && (
          <div className="space-y-6">
            <AIAnalysis
              analysis={aiAnalysis}
              isLoading={isAnalyzing}
              onAnalyze={handleAiAnalysis}
              canAnalyze={aiAnalysisService.canAnalyze({
                providerId: selectedProvider,
                apiKey,
                customEndpoint,
              })}
              selectedProvider={selectedProvider}
              onProviderChange={setSelectedProvider}
              apiKey={apiKey}
              onApiKeyChange={setApiKey}
              customEndpoint={customEndpoint}
              onCustomEndpointChange={setCustomEndpoint}
            />
          </div>
        )}
      </main>

      {/* Modal for detailed results */}
      <Modal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        title={`${selectedAttackType} - Detailed Results`}
        size="xl"
      >
        <FacetedDataTable
          data={modalData}
          filters={filters}
          onFiltersChange={setFilters}
        />
      </Modal>

      {/* Toast Notifications */}
      <div className="fixed bottom-4 right-4 space-y-2 z-50">
        {toasts.map((toast) => (
          <Toast key={toast.id} toast={toast} onRemove={removeToast} />
        ))}
      </div>
    </div>
  );
}

export default App;