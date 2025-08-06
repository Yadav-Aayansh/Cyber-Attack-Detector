import React, { useState, useEffect, useMemo } from 'react';
import { Sun, Moon, Download, BarChart3, Shield, History, Menu, X } from 'lucide-react';
import { FileUpload } from './components/FileUpload';
import { AttackTypeCard } from './components/AttackTypeCard';
import { DataTable } from './components/DataTable';
import { Dashboard } from './components/Dashboard';
import { Modal } from './components/Modal';
import { Toast } from './components/Toast';
import { useTheme } from './hooks/useTheme';
import { useToast } from './hooks/useToast';
import { apiService } from './services/api';
import { processLogData, generateAnalysisSummary, exportToCSV, exportToJSON, downloadFile } from './utils/dataProcessing';
import { ATTACK_TYPES } from './config/attackTypes';
import { ProcessedLogEntry, Filters, SavedAnalysis, ScanEndpoint } from './types';

type ActiveTab = 'dashboard' | 'attacks' | 'analysis' | 'history';

function App() {
  const { theme, toggleTheme } = useTheme();
  const { toasts, addToast, removeToast } = useToast();
  
  const [file, setFile] = useState<File | null>(null);
  const [activeTab, setActiveTab] = useState<ActiveTab>('dashboard');
  const [isLoading, setIsLoading] = useState(false);
  const [allResults, setAllResults] = useState<ProcessedLogEntry[]>([]);
  const [savedAnalyses, setSavedAnalyses] = useState<SavedAnalysis[]>([]);
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [selectedAttackType, setSelectedAttackType] = useState<string | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [modalData, setModalData] = useState<ProcessedLogEntry[]>([]);
  const [modalLoading, setModalLoading] = useState(false);
  
  const [filters, setFilters] = useState<Filters>({
    attackType: '',
    statusCode: '',
    ip: '',
    dateRange: '',
    severity: '',
    search: ''
  });

  // Load saved analyses from localStorage
  useEffect(() => {
    const saved = localStorage.getItem('logguard-analyses');
    if (saved) {
      try {
        setSavedAnalyses(JSON.parse(saved));
      } catch (error) {
        console.error('Failed to load saved analyses:', error);
      }
    }
  }, []);

  // Save analyses to localStorage
  useEffect(() => {
    localStorage.setItem('logguard-analyses', JSON.stringify(savedAnalyses));
  }, [savedAnalyses]);

  const summary = useMemo(() => generateAnalysisSummary(allResults), [allResults]);

  const attackTypeCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    ATTACK_TYPES.forEach(type => {
      counts[type.name] = allResults.filter(result => result.attack_type === type.name).length;
    });
    return counts;
  }, [allResults]);

  const handleFileUpload = async (uploadedFile: File) => {
    setFile(uploadedFile);
    setIsLoading(true);
    addToast('Starting log analysis...', 'info');

    try {
      // Scan all attack types in parallel
      const results = await apiService.scanAllTypes(uploadedFile);
      
      // Process and combine all results
      const processedResults: ProcessedLogEntry[] = [];
      
      for (const [endpoint, response] of Object.entries(results)) {
        const attackType = ATTACK_TYPES.find(type => type.endpoint === endpoint)?.name || endpoint;
        const processed = processLogData(response.results, attackType);
        processedResults.push(...processed);
      }

      setAllResults(processedResults);
      
      // Save analysis if we have results
      if (processedResults.length > 0) {
        const newAnalysis: SavedAnalysis = {
          id: Date.now(),
          name: uploadedFile.name,
          uploadDate: new Date().toISOString(),
          summary: generateAnalysisSummary(processedResults),
          results: processedResults
        };
        setSavedAnalyses(prev => [newAnalysis, ...prev.slice(0, 9)]); // Keep only last 10
      }

      addToast(`Analysis complete! Found ${processedResults.length} potential threats.`, 'success');
      
      // Switch to dashboard tab to show results
      setActiveTab('dashboard');
      
    } catch (error) {
      console.error('Analysis failed:', error);
      addToast('Analysis failed. Please check your connection and try again.', 'error');
    } finally {
      setIsLoading(false);
    }
  };

  const handleViewAttackDetails = async (attackType: string) => {
    if (!file) {
      addToast('Please upload a file first', 'error');
      return;
    }

    const config = ATTACK_TYPES.find(type => type.name === attackType);
    if (!config) return;

    setSelectedAttackType(attackType);
    setIsModalOpen(true);
    setModalLoading(true);

    try {
      const result = await apiService.scanLogs(config.endpoint, { file, limit: 100 });
      const processed = processLogData(result.results, attackType);
      setModalData(processed);
      
      if (processed.length === 0) {
        addToast(`No ${attackType} attacks found`, 'info');
      }
    } catch (error) {
      console.error('Failed to fetch attack details:', error);
      addToast('Failed to load attack details', 'error');
      setModalData([]);
    } finally {
      setModalLoading(false);
    }
  };

  const handleExport = (format: 'csv' | 'json') => {
    if (allResults.length === 0) {
      addToast('No data to export', 'error');
      return;
    }

    const timestamp = new Date().toISOString().split('T')[0];
    const filename = `logguard-analysis-${timestamp}`;

    try {
      if (format === 'csv') {
        const csv = exportToCSV(allResults);
        downloadFile(csv, `${filename}.csv`, 'text/csv');
      } else {
        const json = exportToJSON(allResults);
        downloadFile(json, `${filename}.json`, 'application/json');
      }
      addToast(`Data exported as ${format.toUpperCase()}`, 'success');
    } catch (error) {
      console.error('Export failed:', error);
      addToast('Export failed', 'error');
    }
  };

  const handleLoadAnalysis = (analysis: SavedAnalysis) => {
    setAllResults(analysis.results);
    setActiveTab('dashboard');
    addToast(`Loaded analysis: ${analysis.name}`, 'success');
  };

  return (
    <div className={`min-h-screen transition-colors duration-200 ${
      theme === 'light' 
        ? 'bg-gradient-to-br from-gray-50 to-gray-100 text-gray-900' 
        : 'bg-gradient-to-br from-gray-900 to-gray-800 text-white'
    }`}>
      {/* Navigation */}
      <nav className={`sticky top-0 z-10 backdrop-blur-sm border-b transition-colors duration-200 ${
        theme === 'light' 
          ? 'bg-white/80 border-gray-200' 
          : 'bg-gray-900/80 border-gray-700'
      }`}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-4">
              <Shield className="w-8 h-8 text-blue-600" />
              <h1 className="text-xl font-bold">LogGuard</h1>
            </div>

            {/* Desktop Navigation */}
            <div className="hidden md:flex items-center space-x-6">
              <button
                onClick={() => setActiveTab('dashboard')}
                className={`flex items-center space-x-2 px-3 py-2 rounded-lg font-medium transition-colors ${
                  activeTab === 'dashboard'
                    ? 'bg-blue-100 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300'
                    : 'hover:bg-gray-100 dark:hover:bg-gray-700'
                }`}
              >
                <BarChart3 className="w-4 h-4" />
                <span>Dashboard</span>
              </button>

              <button
                onClick={() => setActiveTab('attacks')}
                className={`flex items-center space-x-2 px-3 py-2 rounded-lg font-medium transition-colors ${
                  activeTab === 'attacks'
                    ? 'bg-blue-100 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300'
                    : 'hover:bg-gray-100 dark:hover:bg-gray-700'
                }`}
              >
                <Shield className="w-4 h-4" />
                <span>Attack Types</span>
              </button>

              <button
                onClick={() => setActiveTab('analysis')}
                className={`flex items-center space-x-2 px-3 py-2 rounded-lg font-medium transition-colors ${
                  activeTab === 'analysis'
                    ? 'bg-blue-100 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300'
                    : 'hover:bg-gray-100 dark:hover:bg-gray-700'
                }`}
              >
                <span>Detailed Analysis</span>
              </button>

              <button
                onClick={() => setActiveTab('history')}
                className={`flex items-center space-x-2 px-3 py-2 rounded-lg font-medium transition-colors ${
                  activeTab === 'history'
                    ? 'bg-blue-100 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300'
                    : 'hover:bg-gray-100 dark:hover:bg-gray-700'
                }`}
              >
                <History className="w-4 h-4" />
                <span>History</span>
              </button>

              {/* Export Buttons */}
              {allResults.length > 0 && (
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => handleExport('csv')}
                    className="flex items-center space-x-2 px-3 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg font-medium transition-colors"
                  >
                    <Download className="w-4 h-4" />
                    <span>CSV</span>
                  </button>
                  <button
                    onClick={() => handleExport('json')}
                    className="flex items-center space-x-2 px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors"
                  >
                    <Download className="w-4 h-4" />
                    <span>JSON</span>
                  </button>
                </div>
              )}

              <button
                onClick={toggleTheme}
                className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
              >
                {theme === 'light' ? <Moon className="w-5 h-5" /> : <Sun className="w-5 h-5" />}
              </button>
            </div>

            {/* Mobile Menu Button */}
            <button
              onClick={() => setIsMenuOpen(!isMenuOpen)}
              className="md:hidden p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700"
            >
              {isMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
            </button>
          </div>

          {/* Mobile Navigation */}
          {isMenuOpen && (
            <div className="md:hidden border-t border-gray-200 dark:border-gray-700 py-4 space-y-2">
              {[
                { key: 'dashboard', label: 'Dashboard', icon: BarChart3 },
                { key: 'attacks', label: 'Attack Types', icon: Shield },
                { key: 'analysis', label: 'Detailed Analysis', icon: null },
                { key: 'history', label: 'History', icon: History },
              ].map(({ key, label, icon: Icon }) => (
                <button
                  key={key}
                  onClick={() => {
                    setActiveTab(key as ActiveTab);
                    setIsMenuOpen(false);
                  }}
                  className={`w-full flex items-center space-x-2 px-3 py-2 rounded-lg font-medium transition-colors ${
                    activeTab === key
                      ? 'bg-blue-100 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300'
                      : 'hover:bg-gray-100 dark:hover:bg-gray-700'
                  }`}
                >
                  {Icon && <Icon className="w-4 h-4" />}
                  <span>{label}</span>
                </button>
              ))}
              <button
                onClick={toggleTheme}
                className="w-full flex items-center space-x-2 px-3 py-2 rounded-lg font-medium hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
              >
                {theme === 'light' ? <Moon className="w-4 h-4" /> : <Sun className="w-4 h-4" />}
                <span>{theme === 'light' ? 'Dark Mode' : 'Light Mode'}</span>
              </button>
            </div>
          )}
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold mb-4">Advanced Log Security Analysis</h1>
          <p className="text-xl opacity-80 max-w-3xl mx-auto">
            Upload your Apache/Nginx logs for comprehensive security threat detection and analysis.
            Powered by advanced pattern recognition and machine learning algorithms.
          </p>
        </div>

        {/* File Upload */}
        <div className="mb-8">
          <FileUpload onFileSelect={handleFileUpload} isLoading={isLoading} />
        </div>

        {/* Tab Content */}
        {activeTab === 'dashboard' && (
          <Dashboard data={allResults} summary={summary} isLoading={isLoading} />
        )}

        {activeTab === 'attacks' && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
            {ATTACK_TYPES.map((config) => (
              <AttackTypeCard
                key={config.name}
                config={config}
                count={attackTypeCounts[config.name] || 0}
                isLoading={isLoading}
                onViewDetails={() => handleViewAttackDetails(config.name)}
              />
            ))}
          </div>
        )}

        {activeTab === 'analysis' && (
          <DataTable
            data={allResults}
            isLoading={isLoading}
            filters={filters}
            onFiltersChange={setFilters}
          />
        )}

        {activeTab === 'history' && (
          <div className="space-y-6">
            <div className="text-center">
              <h2 className="text-2xl font-bold mb-2">Analysis History</h2>
              <p className="text-gray-600 dark:text-gray-300">
                View and reload your previous log analyses
              </p>
            </div>

            {savedAnalyses.length === 0 ? (
              <div className="text-center py-12">
                <History className="w-16 h-16 text-gray-400 mx-auto mb-4" />
                <p className="text-xl text-gray-500 dark:text-gray-400 mb-2">No saved analyses</p>
                <p className="text-gray-400 dark:text-gray-500">Upload a log file to create your first analysis</p>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {savedAnalyses.map((analysis) => (
                  <div
                    key={analysis.id}
                    className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-lg border border-gray-200 dark:border-gray-700 hover:shadow-xl transition-all duration-200"
                  >
                    <div className="mb-4">
                      <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2 truncate">
                        {analysis.name}
                      </h3>
                      <p className="text-sm text-gray-500 dark:text-gray-400">
                        {new Date(analysis.uploadDate).toLocaleDateString()} at{' '}
                        {new Date(analysis.uploadDate).toLocaleTimeString()}
                      </p>
                    </div>

                    <div className="space-y-2 mb-4">
                      <div className="flex justify-between text-sm">
                        <span className="text-gray-600 dark:text-gray-300">Total Threats:</span>
                        <span className="font-semibold text-red-600 dark:text-red-400">
                          {analysis.summary.totalThreats}
                        </span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-gray-600 dark:text-gray-300">Unique IPs:</span>
                        <span className="font-semibold">{analysis.summary.topAttackers.length}</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-gray-600 dark:text-gray-300">Attack Types:</span>
                        <span className="font-semibold">
                          {Object.keys(analysis.summary.attackTypeCounts).length}
                        </span>
                      </div>
                    </div>

                    <button
                      onClick={() => handleLoadAnalysis(analysis)}
                      className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors"
                    >
                      Load Analysis
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Attack Details Modal */}
        <Modal
          isOpen={isModalOpen}
          onClose={() => setIsModalOpen(false)}
          title={`${selectedAttackType} Details`}
          size="xl"
        >
          {modalLoading ? (
            <div className="text-center py-8">
              <div className="w-8 h-8 border-4 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
              <p className="text-gray-600 dark:text-gray-300">Loading attack details...</p>
            </div>
          ) : modalData.length > 0 ? (
            <DataTable
              data={modalData}
              isLoading={false}
              filters={filters}
              onFiltersChange={setFilters}
            />
          ) : (
            <div className="text-center py-8">
              <Shield className="w-16 h-16 text-gray-400 mx-auto mb-4" />
              <p className="text-xl text-gray-500 dark:text-gray-400">No threats detected</p>
              <p className="text-gray-400 dark:text-gray-500">This attack type was not found in your logs</p>
            </div>
          )}
        </Modal>
      </main>

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