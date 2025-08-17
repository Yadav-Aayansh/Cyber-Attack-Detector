import ATTACK_TYPES from './attackTypes.js';
import { parseLogFile, DETECTORS, processLogData } from './threatDetectors.js';

window.ThreatAnalysis = {
    ATTACK_TYPES,
    parseLogFile,
    DETECTORS,
    processLogData
};

const { createApp } = Vue;

createApp({
    data() {
        return {
            darkMode: false,
            activeTab: 'security-analysis',
            isDragOver: false,
            selectedFile: null,
            isLoadingDemo: false,
            logData: null,
            logContent: '',
            attackTypes: [],
            threatResults: {},
            scanningStates: {},
            isRunningAllScans: false,
            showFunctionModal: false,
            currentFunctionName: '',
            currentFunctionCode: '',
            showResultsModal: false,
            currentResults: [],
            currentResultsTitle: '',
            // Filters for results modal
            resultsFilters: {
                search: '',
                ipAddress: '',
                attackType: [],
                httpMethod: [],
                statusCode: []
            },
            resultsCurrentPage: 1,
            resultsPerPage: 50,
            // Data table filters
            dataTableFilters: {
                search: '',
                ipAddress: '',
                attackType: [],
                httpMethod: [],
                statusCode: []
            },
            dataTableCurrentPage: 1,
            dataTablePerPage: 50,
            tabs: [
                {
                    id: 'security-analysis',
                    name: 'Security Analysis',
                    icon: 'fas fa-shield-alt'
                },
                // {
                //     id: 'dashboard',
                //     name: 'Dashboard',
                //     icon: 'fas fa-chart-bar'
                // },
                {
                    id: 'data-table',
                    name: 'Data Table',
                    icon: 'fas fa-table'
                }
            ]
        };
    },
    mounted() {
        this.initializeAttackTypes();
        // Check for saved theme preference or default to light mode
        const savedTheme = localStorage.getItem('theme');
        if (savedTheme) {
            this.darkMode = savedTheme === 'dark';
        } else {
            // Check system preference
            this.darkMode = window.matchMedia('(prefers-color-scheme: dark)').matches;
        }
        this.updateTheme();
    },
    methods: {
        async initializeAttackTypes() {
            try {
                const module = await import('./attackTypes.js');
                this.attackTypes = module.default;
                
                // Initialize scanning states
                this.attackTypes.forEach(attack => {
                    this.scanningStates[attack.endpoint] = false;
                    this.threatResults[attack.endpoint] = [];
                });
            } catch (error) {
                console.error('Failed to load attack types:', error);
            }
        },
        toggleDarkMode() {
            this.darkMode = !this.darkMode;
            this.updateTheme();
            localStorage.setItem('theme', this.darkMode ? 'dark' : 'light');
        },
        updateTheme() {
            if (this.darkMode) {
                document.documentElement.classList.add('dark');
            } else {
                document.documentElement.classList.remove('dark');
            }
        },
        handleFileDrop(event) {
            this.isDragOver = false;
            const files = event.dataTransfer.files;
            if (files.length > 0) {
                this.processFile(files[0]);
            }
        },
        handleFileSelect(event) {
            const files = event.target.files;
            if (files.length > 0) {
                this.processFile(files[0]);
            }
        },
        async processFile(file) {
            // Validate file type
            const allowedTypes = ['.log', '.txt', '.zip', '.gz'];
            const fileExtension = '.' + file.name.split('.').pop().toLowerCase();
            
            if (!allowedTypes.includes(fileExtension)) {
                alert('Please select a valid log file (.log, .txt, .zip, .gz)');
                return;
            }
            
            // Validate file size (100MB limit)
            const maxSize = 100 * 1024 * 1024; // 100MB in bytes
            if (file.size > maxSize) {
                alert('File size exceeds 100MB limit');
                return;
            }
            
            this.selectedFile = file;
            
            // Process the file content
            await this.processFileContent(file);
            
            // Here you would typically upload the file or process it
            console.log('File selected:', file.name, 'Size:', this.formatFileSize(file.size));
            
            // Show success message
            this.showNotification('File uploaded successfully!', 'success');
        },
        async processFileContent(file) {
            try {
                let content = '';
                
                // Check if file is compressed
                if (file.name.toLowerCase().endsWith('.zip')) {
                    content = await this.unzipFile(file);
                } else if (file.name.toLowerCase().endsWith('.gz')) {
                    content = await this.ungzipFile(file);
                } else {
                    content = await this.readTextFile(file);
                }
                
                this.logContent = content;
                await this.parseLogContent(content);
                
            } catch (error) {
                console.error('Error processing file:', error);
                this.showNotification(`Error processing file: ${error.message}`, 'error');
            }
        },
        async unzipFile(file) {
            try {
                const zip = new JSZip();
                const zipContent = await zip.loadAsync(file);
                
                // Get all files in the zip
                const fileNames = Object.keys(zipContent.files).filter(name => !zipContent.files[name].dir);
                
                if (fileNames.length === 0) {
                    throw new Error('No files found in ZIP archive');
                }
                
                // Find the first .log or .txt file, or just take the first file
                let targetFile = fileNames.find(filename => {
                    const lower = filename.toLowerCase();
                    return lower.endsWith('.log') || lower.endsWith('.txt');
                });
                
                if (!targetFile) {
                    targetFile = fileNames[0]; // Take first file if no .log/.txt found
                }
                
                console.log(`Extracting file: ${targetFile} from ZIP`);
                const content = await zipContent.files[targetFile].async('text');
                
                if (!content || content.trim().length === 0) {
                    throw new Error('Extracted file is empty');
                }
                
                return content;
            } catch (error) {
                console.error('Error unzipping file:', error);
                throw new Error(`Failed to extract ZIP file: ${error.message}`);
            }
        },
        async ungzipFile(file) {
            try {
                // For .gz files, we'll use JSZip which can handle some gzip files
                // If it fails, we'll try to read as text
                try {
                    const zip = new JSZip();
                    const zipContent = await zip.loadAsync(file);
                    const fileNames = Object.keys(zipContent.files).filter(name => !zipContent.files[name].dir);
                    
                    if (fileNames.length > 0) {
                        const targetFile = fileNames[0];
                        console.log(`Extracting file: ${targetFile} from GZ`);
                        return await zipContent.files[targetFile].async('text');
                    }
                } catch (gzipError) {
                    console.log('JSZip failed for GZ, trying as text file:', gzipError.message);
                }
                
                // Fallback: try to read as text file
                return await this.readTextFile(file);
            } catch (error) {
                console.error('Error processing GZ file:', error);
                throw new Error(`Failed to process GZ file: ${error.message}`);
            }
        },
        async readTextFile(file) {
            return new Promise((resolve, reject) => {
                const reader = new FileReader();
                reader.onload = e => resolve(e.target.result);
                reader.onerror = e => reject(new Error('Failed to read file'));
                reader.readAsText(file);
            });
        },
        async parseLogContent(content) {
            try {
                if (!content || content.trim().length === 0) {
                    throw new Error('File content is empty');
                }
                
                const { parseLogFile } = await import('./threatDetectors.js');
                this.logData = parseLogFile(content);
                
                if (!this.logData || this.logData.length === 0) {
                    throw new Error('No valid log entries found in file');
                }
                
                console.log(`Successfully parsed ${this.logData.length} log entries`);
                this.showNotification(`Parsed ${this.logData.length} log entries successfully`, 'success');
                
            } catch (error) {
                console.error('Error parsing log content:', error);
                throw new Error(`Failed to parse log file: ${error.message}`);
            }
        },
        formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        },
        async loadDemo() {
            if (this.isLoadingDemo) return;
            
            this.isLoadingDemo = true;
            
            try {
                this.showNotification('Loading demo dataset...', 'info');
                
                const response = await fetch('https://raw.githubusercontent.com/Yadav-Aayansh/gramener-datasets/refs/heads/add-server-logs/server_logs.zip');
                
                if (!response.ok) {
                    throw new Error(`Failed to fetch demo dataset: ${response.statusText}`);
                }
                
                const blob = await response.blob();
                const file = new File([blob], 'server_logs.zip', { type: 'application/zip' });
                
                // Set as selected file and process content
                this.selectedFile = file;
                await this.processFileContent(file);
                
                this.showNotification(`Demo dataset "${file.name}" loaded successfully!`, 'success');
                
            } catch (error) {
                console.error('Failed to load demo dataset:', error);
                this.showNotification(`Failed to load demo dataset: ${error.message}`, 'error');
            } finally {
                this.isLoadingDemo = false;
            }
        },
        getSeverityIcon(severity) {
            const icons = {
                high: { icon: 'fas fa-exclamation-triangle', bgClass: 'bg-red-100 dark:bg-red-900/30', textClass: 'text-red-600 dark:text-red-400' },
                medium: { icon: 'fas fa-exclamation-circle', bgClass: 'bg-yellow-100 dark:bg-yellow-900/30', textClass: 'text-yellow-600 dark:text-yellow-400' },
                low: { icon: 'fas fa-info-circle', bgClass: 'bg-green-100 dark:bg-green-900/30', textClass: 'text-green-600 dark:text-green-400' }
            };
            return icons[severity] || icons.medium;
        },
        getSeverityBadge(severity) {
            const badges = {
                high: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
                medium: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400',
                low: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
            };
            return badges[severity] || badges.medium;
        },
        async scanThreat(endpoint) {
            if (!this.logData || this.scanningStates[endpoint]) return;
            
            this.scanningStates[endpoint] = true;
            
            try {
                const { DETECTORS } = await import('./threatDetectors.js');
                const detector = DETECTORS[endpoint];
                
                if (!detector) {
                    throw new Error(`No detector found for ${endpoint}`);
                }
                
                // Simulate processing time for better UX
                await new Promise(resolve => setTimeout(resolve, 1000));
                
                const results = detector(this.logData);
                this.threatResults[endpoint] = results;
                
                const attackType = this.attackTypes.find(a => a.endpoint === endpoint);
                this.showNotification(
                    `${attackType?.name || endpoint} scan completed. Found ${results.length} threats.`,
                    results.length > 0 ? 'warning' : 'success'
                );
                
            } catch (error) {
                console.error(`Error scanning ${endpoint}:`, error);
                this.showNotification(`Error scanning ${endpoint}: ${error.message}`, 'error');
            } finally {
                this.scanningStates[endpoint] = false;
            }
        },
        async runAllScans() {
            if (!this.logData || this.isRunningAllScans) return;
            
            this.isRunningAllScans = true;
            
            try {
                this.showNotification('Running all security scans...', 'info');
                
                // Run all scans in parallel
                const scanPromises = this.attackTypes.map(attack => 
                    this.scanThreat(attack.endpoint)
                );
                
                await Promise.all(scanPromises);
                
                const totalThreats = Object.values(this.threatResults).reduce((sum, results) => sum + results.length, 0);
                this.showNotification(
                    `All scans completed. Found ${totalThreats} total threats.`,
                    totalThreats > 0 ? 'warning' : 'success'
                );
                
            } catch (error) {
                console.error('Error running all scans:', error);
                this.showNotification(`Error running scans: ${error.message}`, 'error');
            } finally {
                this.isRunningAllScans = false;
            }
        },
        async viewThreatFunction(endpoint) {
            try {
                const { DETECTORS } = await import('./threatDetectors.js');
                const detector = DETECTORS[endpoint];
                
                if (!detector) {
                    this.showNotification(`No detector found for ${endpoint}`, 'error');
                    return;
                }
                
                const attackType = this.attackTypes.find(a => a.endpoint === endpoint);
                this.currentFunctionName = attackType?.name || endpoint;
                this.currentFunctionCode = detector.toString();
                this.showFunctionModal = true;
                
            } catch (error) {
                console.error('Error viewing function:', error);
                this.showNotification(`Error viewing function: ${error.message}`, 'error');
            }
        },
        viewResults(endpoint) {
            const results = this.threatResults[endpoint] || [];
            const attackType = this.attackTypes.find(a => a.endpoint === endpoint);
            
            this.currentResults = results;
            this.currentResultsTitle = attackType?.name || endpoint;
            this.showResultsModal = true;
            this.resultsCurrentPage = 1;
            this.resetResultsFilters();
        },
        resetResultsFilters() {
            this.resultsFilters = {
                search: '',
                ipAddress: '',
                attackType: [],
                httpMethod: [],
                statusCode: []
            };
        },
        resetDataTableFilters() {
            this.dataTableFilters = {
                search: '',
                ipAddress: '',
                attackType: [],
                httpMethod: [],
                statusCode: []
            };
        },
        getFilteredResults(results, filters) {
            return results.filter(result => {
                // Search filter
                if (filters.search) {
                    const searchTerm = filters.search.toLowerCase();
                    const searchableFields = [
                        result.ip, result.path, result.user_agent, 
                        result.referrer, result.suspicion_reason
                    ].join(' ').toLowerCase();
                    
                    if (!searchableFields.includes(searchTerm)) {
                        return false;
                    }
                }
                
                // IP Address filter
                if (filters.ipAddress && !result.ip.includes(filters.ipAddress)) {
                    return false;
                }
                
                // Attack Type filter
                if (filters.attackType.length > 0) {
                    const attackTypeName = this.getAttackTypeName(result);
                    if (!filters.attackType.includes(attackTypeName)) {
                        return false;
                    }
                }
                
                // HTTP Method filter
                if (filters.httpMethod.length > 0 && !filters.httpMethod.includes(result.method)) {
                    return false;
                }
                
                // Status Code filter
                if (filters.statusCode.length > 0 && !filters.statusCode.includes(result.status)) {
                    return false;
                }
                
                return true;
            });
        },
        getAttackTypeName(result) {
            // Try to determine attack type from suspicion reason or other fields
            const reason = result.suspicion_reason?.toLowerCase() || '';
            
            if (reason.includes('sql injection')) return 'SQL Injection';
            if (reason.includes('path traversal')) return 'Path Traversal';
            if (reason.includes('bot')) return 'Bot Detection';
            if (reason.includes('lfi') || reason.includes('rfi')) return 'LFI/RFI Attacks';
            if (reason.includes('wordpress')) return 'WordPress Probes';
            if (reason.includes('brute force')) return 'Brute Force';
            if (reason.includes('error')) return 'HTTP Errors';
            if (reason.includes('internal ip')) return 'Internal IP Access';
            
            return 'Unknown';
        },
        getPaginatedResults(results, currentPage, perPage) {
            const startIndex = (currentPage - 1) * perPage;
            const endIndex = startIndex + perPage;
            return results.slice(startIndex, endIndex);
        },
        getTotalPages(totalItems, perPage) {
            return Math.ceil(totalItems / perPage);
        },
        getAllResults() {
            const allResults = [];
            Object.keys(this.threatResults).forEach(endpoint => {
                const results = this.threatResults[endpoint] || [];
                results.forEach(result => {
                    allResults.push({
                        ...result,
                        attack_type: this.getAttackTypeName(result)
                    });
                });
            });
            return allResults;
        },
        getUniqueValues(results, field) {
            const values = results.map(result => result[field]).filter(Boolean);
            return [...new Set(values)].sort();
        },
        toggleFilter(filterArray, value) {
            const index = filterArray.indexOf(value);
            if (index > -1) {
                filterArray.splice(index, 1);
            } else {
                filterArray.push(value);
            }
        },
        clearAllFilters(filterType) {
            if (filterType === 'results') {
                this.resetResultsFilters();
            } else if (filterType === 'dataTable') {
                this.resetDataTableFilters();
                this.dataTableCurrentPage = 1;
            }
        },
        formatTimestamp(timestamp) {
            try {
                const date = new Date(timestamp);
                return date.toLocaleString();
            } catch {
                return timestamp;
            }
        },
        getStatusBadgeClass(status) {
            const statusCode = parseInt(status);
            if (statusCode >= 200 && statusCode < 300) return 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400';
            if (statusCode >= 300 && statusCode < 400) return 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400';
            if (statusCode >= 400 && statusCode < 500) return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400';
            if (statusCode >= 500) return 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400';
            return 'bg-gray-100 text-gray-800 dark:bg-gray-900/30 dark:text-gray-400';
        },
        showNotification(message, type = 'info') {
            // Simple notification system
            const notification = document.createElement('div');
            notification.className = `fixed bottom-6 right-4 px-6 py-3 rounded-lg text-white z-50 ${
                type === 'success' ? 'bg-green-500' : 
                type === 'error' ? 'bg-red-500' : 
                type === 'warning' ? 'bg-yellow-500' :
                'bg-blue-500'
            }`;
            notification.textContent = message;
            
            document.body.appendChild(notification);
            
            // Auto remove after 3 seconds
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 1500);
        }
    }
}).mount('#app');