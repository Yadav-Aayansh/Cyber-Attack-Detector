// Global State
let selectedFile = null;
let allResults = [];
let scanResults = {};
let isScanning = {};
let activeView = 'overview';
let theme = localStorage.getItem('cyberdetect-theme') || 'light';
let toasts = [];
let selectedAttackType = null;
let toastIdCounter = 0;

// Attack Types Configuration
const ATTACK_TYPES = [
    {
        name: 'SQL Injection',
        description: 'Attempts to inject malicious SQL code into database queries',
        severity: 'high',
        color: '#DC2626',
        endpoint: 'sql-injection'
    },
    {
        name: 'Path Traversal',
        description: 'Attempts to access files outside the web root directory',
        severity: 'high',
        color: '#EA580C',
        endpoint: 'path-traversal'
    },
    {
        name: 'Bot Detection',
        description: 'Automated bot and crawler activity detection',
        severity: 'medium',
        color: '#CA8A04',
        endpoint: 'bots'
    },
    {
        name: 'LFI/RFI Attacks',
        description: 'Local and Remote File Inclusion attack attempts',
        severity: 'high',
        color: '#DC2626',
        endpoint: 'lfi-rfi'
    },
    {
        name: 'WordPress Probes',
        description: 'WordPress-specific vulnerability scanning attempts',
        severity: 'medium',
        color: '#7C3AED',
        endpoint: 'wp-probe'
    },
    {
        name: 'Brute Force',
        description: 'Password brute force and credential stuffing attacks',
        severity: 'high',
        color: '#B91C1C',
        endpoint: 'brute-force'
    },
    {
        name: 'HTTP Errors',
        description: 'Suspicious HTTP error patterns and responses',
        severity: 'low',
        color: '#059669',
        endpoint: 'errors'
    },
    {
        name: 'Internal IP Access',
        description: 'Unauthorized access attempts to internal IP ranges',
        severity: 'medium',
        color: '#0284C7',
        endpoint: 'internal-ip'
    }
];

// Utility Functions
function parseTimestamp(timestamp) {
    try {
        const match = timestamp.match(/(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})/);
        if (!match) return timestamp;

        const [, day, monthName, year, hour, minute, second, timezone] = match;

        const monthMap = {
            'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04',
            'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
            'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'
        };

        const month = monthMap[monthName];
        if (!month) return timestamp;

        const isoString = `${year}-${month}-${day}T${hour}:${minute}:${second}${timezone}`;
        const date = new Date(isoString);

        if (isNaN(date.getTime())) return timestamp;
        return date.toISOString();
    } catch {
        return timestamp;
    }
}

function parseLogFile(content) {
    const lines = content.split('\n');
    const parsed = [];
    const logPattern = /(?<ip>\S+) - - \[(?<timestamp>.*?)\] "(?<method>\S+) (?<path>\S+) (?<protocol>[^"]+)" (?<status>\d{3}) (?<bytes>\S+) "(?<referrer>[^"]*)" "(?<user_agent>[^"]*)" (?<host>\S+) (?<server_ip>\S+)/;

    for (const line of lines) {
        const match = line.match(logPattern);
        if (match && match.groups) {
            parsed.push({
                ip: match.groups.ip,
                timestamp: parseTimestamp(match.groups.timestamp),
                method: match.groups.method,
                path: match.groups.path,
                protocol: match.groups.protocol,
                status: match.groups.status,
                bytes: match.groups.bytes,
                referrer: match.groups.referrer,
                user_agent: match.groups.user_agent,
                host: match.groups.host,
                server_ip: match.groups.server_ip,
            });
        }
    }

    return parsed;
}

// Detector Functions
function detectSqlInjection(entries) {
    const patterns = [
        "union\\s+(all\\s+)?select",
        "select\\s+.*\\s+from",
        "select\\s+\\*",
        "(and|or)\\s+\\d+\\s*[=<>!]+\\s*\\d+",
        "(and|or)\\s+['\"]?[a-z]+['\"]?\\s*[=<>!]+\\s*['\"]?[a-z]+['\"]?",
        "(and|or)\\s+\\d+\\s*(and|or)\\s+\\d+",
        "(sleep|waitfor|delay)\\s*\\(\\s*\\d+\\s*\\)",
        "benchmark\\s*\\(\\s*\\d+",
        "pg_sleep\\s*\\(\\s*\\d+\\s*\\)",
        "(convert|cast|char)\\s*\\(",
        "concat\\s*\\(",
        "group_concat\\s*\\(",
        "having\\s+\\d+\\s*[=<>!]+\\s*\\d+",
        "(admin|user|login)['\"]?\\s*(=|like)\\s*['\"]?\\s*(or|and)",
        "['\"]\\s*(or|and)\\s*['\"]?[^'\"]*['\"]?\\s*(=|like)",
        "['\"]\\s*(or|and)\\s*\\d+\\s*[=<>!]+\\s*\\d+",
        "(drop|delete|truncate|insert|update)\\s+(table|from|into)",
        "(exec|execute|sp_|xp_)\\w*",
        "(information_schema|sys\\.|mysql\\.|pg_)",
        "(load_file|into\\s+outfile|dumpfile)",
        "(--|#|\\*/|\\*\\*)",
        "/\\*.*\\*/",
        "(%27|%22|%2d%2d|%23)",
        "(0x[0-9a-f]+)",
        "(char\\s*\\(\\s*\\d+)",
    ];

    const sqliRegex = new RegExp(
        patterns.map(pattern => `(${pattern})`).join('|'),
        'gim'
    );

    const suspicious = entries.filter(entry => {
        if (!entry.path) return false;
        const decodedPath = decodeURIComponent(entry.path);
        return sqliRegex.test(decodedPath);
    });

    return suspicious.map(entry => ({
        ...entry,
        suspicion_reason: 'SQL injection pattern detected'
    }));
}

function detectPathTraversal(entries) {
    const suspicious = entries.filter(entry => {
        const path = entry.path;
        if (!path) return false;

        const hasTraversalPattern = new RegExp('(\\.\\./|%2e%2e%2f|%2e%2f|%2f\\.\\.|/\\.{2})', 'i').test(path);
        const hasExcessiveDepth = (path.match(/\//g) || []).length > 15;

        return hasTraversalPattern || hasExcessiveDepth;
    });

    return suspicious.map(entry => ({
        ...entry,
        suspicion_reason: 'Path traversal pattern detected'
    }));
}

function detectBots(entries) {
    const CRAWLERS = [
        'googlebot', 'bingbot', 'baiduspider', 'yandexbot',
        'duckduckbot', 'slurp', 'facebookexternalhit', 'twitterbot',
        'applebot', 'linkedinbot', 'petalbot', 'semrushbot'
    ];

    const CLIENT_LIBS = [
        'curl', 'wget', 'httpclient', 'python-requests', 'aiohttp',
        'okhttp', 'java/', 'libwww-perl', 'go-http-client', 'restsharp',
        'scrapy', 'httpie'
    ];

    function classifyUserAgent(ua) {
        const userAgent = ua.toLowerCase();

        if (CRAWLERS.some(crawler => userAgent.includes(crawler))) {
            return "Crawler Bot";
        }

        if (CLIENT_LIBS.some(lib => userAgent.includes(lib))) {
            return "Client Library Bot";
        }

        if (userAgent.trim() === '' || userAgent.length < 10 || !userAgent.includes('mozilla')) {
            return "Suspicious User-Agent";
        }

        return null;
    }

    const bots = entries.filter(entry => {
        const botType = classifyUserAgent(entry.user_agent);
        return botType !== null;
    });

    return bots.map(entry => ({
        ...entry,
        suspicion_reason: classifyUserAgent(entry.user_agent) || 'Bot detected'
    }));
}

function detectLfiRfi(entries) {
    const pattern = /(etc\/passwd|proc\/self\/environ|input_file=|data:text)/i;

    const suspicious = entries.filter(entry => {
        return pattern.test(entry.path);
    });

    return suspicious.map(entry => ({
        ...entry,
        suspicion_reason: 'LFI/RFI pattern detected'
    }));
}

function detectWpProbe(entries) {
    const pattern = /(\.php|\/wp-|xmlrpc\.php|\?author=|\?p=)/i;

    const suspicious = entries.filter(entry => {
        return pattern.test(entry.path);
    });

    return suspicious.map(entry => ({
        ...entry,
        suspicion_reason: 'WordPress probe detected'
    }));
}

function detectBruteForce(entries) {
    const loginPattern = /(login|admin|signin|wp-login\.php)/i;
    const badStatuses = ['401', '403', '429'];

    const suspicious = entries.filter(entry => {
        return loginPattern.test(entry.path) && badStatuses.includes(entry.status);
    });

    return suspicious.map(entry => ({
        ...entry,
        suspicion_reason: 'Brute force attempt detected'
    }));
}

function detectErrors(entries) {
    const badStatuses = ['403', '404', '406', '500', '502'];

    const errors = entries.filter(entry => {
        return badStatuses.includes(entry.status);
    });

    return errors.map(entry => ({
        ...entry,
        suspicion_reason: `HTTP error status: ${entry.status}`
    }));
}

function detectInternalIp(entries) {
    const internal = entries.filter(entry => {
        const ip = entry.ip;
        return ip.startsWith('192.168.') ||
            ip.startsWith('10.') ||
            ip.startsWith('127.') ||
            ip.startsWith('172.');
    });

    return internal.map(entry => ({
        ...entry,
        suspicion_reason: 'Internal IP address detected'
    }));
}

// Detector mapping
const DETECTORS = {
    'sql-injection': detectSqlInjection,
    'path-traversal': detectPathTraversal,
    'bots': detectBots,
    'lfi-rfi': detectLfiRfi,
    'wp-probe': detectWpProbe,
    'brute-force': detectBruteForce,
    'errors': detectErrors,
    'internal-ip': detectInternalIp,
};

// Data Processing Functions
function processLogData(entries, attackType) {
    return entries.map(entry => ({
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
        suspicion_reason: entry.suspicion_reason || '',
        attack_type: attackType,
    }));
}

function exportToCSV(data) {
    const headers = [
        'IP', 'Timestamp', 'Method', 'Path', 'Protocol', 'Status', 'Bytes',
        'Referrer', 'User Agent', 'Host', 'Server IP', 'Suspicion Reason', 'Attack Type'
    ];

    const csvContent = [
        headers.join(','),
        ...data.map(row => [
            row.ip,
            row.timestamp,
            row.method,
            `"${row.path.replace(/"/g, '""')}"`,
            row.protocol,
            row.status,
            row.bytes,
            `"${row.referrer.replace(/"/g, '""')}"`,
            `"${row.user_agent.replace(/"/g, '""')}"`,
            row.host,
            row.server_ip,
            `"${row.suspicion_reason.replace(/"/g, '""')}"`,
            row.attack_type
        ].join(','))
    ].join('\n');

    return csvContent;
}

function exportToJSON(data) {
    return JSON.stringify(data, null, 2);
}

function downloadFile(content, filename, contentType) {
    const blob = new Blob([content], { type: contentType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

// Toast Functions
function addToast(message, type = 'info') {
    const id = toastIdCounter++;
    const toast = { id, message, type };
    toasts.push(toast);

    renderToast(toast);

    setTimeout(() => {
        removeToast(id);
    }, 5000);

    return id;
}

function removeToast(id) {
    toasts = toasts.filter(toast => toast.id !== id);
    const toastElement = document.getElementById(`toast-${id}`);
    if (toastElement) {
        toastElement.remove();
    }
}

function renderToast(toast) {
    const container = document.getElementById('toast-container');
    const toastElement = document.createElement('div');
    toastElement.id = `toast-${toast.id}`;

    const colorMap = {
        success: 'bg-green-500',
        error: 'bg-red-500',
        warning: 'bg-yellow-500',
        info: 'bg-blue-500',
    };

    const iconMap = {
        success: 'check-circle',
        error: 'x-circle',
        warning: 'alert-circle',
        info: 'info',
    };

    toastElement.className = `${colorMap[toast.type]} text-white p-4 rounded-lg shadow-lg flex items-center space-x-3 min-w-80 max-w-md animate-slide-in`;
    toastElement.innerHTML = `
                <i data-lucide="${iconMap[toast.type]}" class="w-5 h-5 flex-shrink-0"></i>
                <p class="flex-1 text-sm font-medium">${toast.message}</p>
                <button onclick="removeToast(${toast.id})" class="p-1 hover:bg-white/20 rounded transition-colors">
                    <i data-lucide="x" class="w-4 h-4"></i>
                </button>
            `;

    container.appendChild(toastElement);
    lucide.createIcons();
}

// Theme Functions
function initTheme() {
    document.documentElement.className = theme;
    localStorage.setItem('cyberdetect-theme', theme);
}

function toggleTheme() {
    theme = theme === 'light' ? 'dark' : 'light';
    document.documentElement.className = theme;
    localStorage.setItem('cyberdetect-theme', theme);
}

// Tab Functions
function setActiveView(view) {
    activeView = view;

    // Hide all tab contents
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.add('hidden');
    });

    // Show active tab content
    document.getElementById(`view-${view}`).classList.remove('hidden');

    // Update tab buttons
    document.querySelectorAll('.nav-tab').forEach(tab => {
        tab.className = 'nav-tab flex items-center space-x-2 px-3 py-4 text-sm font-medium border-b-2 transition-colors border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200';
    });

    const activeTab = document.getElementById(`tab-${view}`);
    activeTab.className = 'nav-tab flex items-center space-x-2 px-3 py-4 text-sm font-medium border-b-2 transition-colors border-blue-500 text-blue-600 dark:text-blue-400';

    // Update dashboard and data table if switching to them
    if (view === 'dashboard') {
        updateDashboard();
    } else if (view === 'data') {
        updateDataTable();
    }
}

// File Processing Functions
async function processFile(file) {
    if (file.name.endsWith('.zip')) {
        try {
            const zip = await JSZip.loadAsync(file);
            const firstFile = Object.keys(zip.files)[0];
            if (firstFile) {
                const decompressedFile = zip.file(firstFile);
                if (decompressedFile) {
                    const content = await decompressedFile.async('text');
                    return content;
                }
            }
        } catch (error) {
            throw new Error('Failed to extract zip file');
        }
    } else if (file.name.endsWith('.gz')) {
        try {
            const arrayBuffer = await file.arrayBuffer();
            const compressedData = new Uint8Array(arrayBuffer);
            const decompressedData = pako.inflate(compressedData);
            const content = new TextDecoder().decode(decompressedData);
            return content;
        } catch (error) {
            throw new Error('Failed to decompress gzip file');
        }
    } else {
        return await file.text();
    }
}

// Analysis Functions
function runAnalysis(attackType, entries) {
    const detector = DETECTORS[attackType.endpoint];
    if (!detector) {
        throw new Error(`No detector found for ${attackType.name}`);
    }

    const suspicious = detector(entries);
    return processLogData(suspicious, attackType.name);
}

async function handleScan(attackType) {
    if (!selectedFile) {
        addToast('Please select a log file first', 'error');
        return;
    }

    isScanning[attackType.name] = true;
    updateAttackCard(attackType);

    try {
        const content = await processFile(selectedFile);
        const entries = parseLogFile(content);
        const results = runAnalysis(attackType, entries);

        scanResults[attackType.name] = results;

        // Update all results
        allResults = allResults.filter(entry => entry.attack_type !== attackType.name);
        allResults.push(...results);

        addToast(`${attackType.name} scan completed: ${results.length} threats found`, 'success');
        updateAttackCard(attackType);
        updateExportButtons();
    } catch (error) {
        console.error('Scan failed:', error);
        addToast(`Failed to scan for ${attackType.name}`, 'error');
    } finally {
        isScanning[attackType.name] = false;
        updateAttackCard(attackType);
    }
}

async function handleRunAll() {
    if (!selectedFile) {
        addToast('Please select a log file first', 'error');
        return;
    }

    addToast('Starting comprehensive security scan...', 'info');

    // Clear previous results
    allResults = [];
    scanResults = {};

    let totalThreats = 0;
    let completedScans = 0;

    try {
        const content = await processFile(selectedFile);
        const entries = parseLogFile(content);

        for (const attackType of ATTACK_TYPES) {
            try {
                isScanning[attackType.name] = true;
                updateAttackCard(attackType);

                const results = runAnalysis(attackType, entries);
                totalThreats += results.length;
                completedScans++;

                scanResults[attackType.name] = results;
                allResults.push(...results);

                addToast(`${attackType.name}: ${results.length} threats found (${completedScans}/${ATTACK_TYPES.length})`, 'success');
                updateAttackCard(attackType);

            } catch (error) {
                console.error(`Scan failed for ${attackType.name}:`, error);
                addToast(`Failed to scan for ${attackType.name}`, 'error');
                completedScans++;
            } finally {
                isScanning[attackType.name] = false;
                updateAttackCard(attackType);
            }
        }

        addToast(`Comprehensive scan completed! Found ${totalThreats} total threats across ${completedScans} attack types`, 'success');
        updateExportButtons();
    } catch (error) {
        console.error('Failed to process file:', error);
        addToast('Failed to process log file', 'error');
    }
}

// UI Update Functions
function updateAttackCard(attackType) {
    const card = document.getElementById(`card-${attackType.endpoint}`);
    if (!card) return;

    const count = scanResults[attackType.name]?.length || 0;
    const loading = isScanning[attackType.name] || false;
    const hasResults = count > 0;

    const countElement = card.querySelector('.threat-count');
    const scanButton = card.querySelector('.scan-button');
    const viewButton = card.querySelector('.view-button');

    if (countElement) {
        countElement.textContent = loading ? '...' : count.toLocaleString();
    }

    if (scanButton) {
        scanButton.disabled = loading;
        scanButton.innerHTML = hasResults ?
            '<i data-lucide="check-circle" class="w-4 h-4"></i><span>Rescan</span>' :
            '<i data-lucide="play" class="w-4 h-4"></i><span>Scan</span>';
    }

    if (viewButton) {
        if (hasResults) {
            viewButton.classList.remove('hidden');
            viewButton.querySelector('span').textContent = `View Results (${count})`;
        } else {
            viewButton.classList.add('hidden');
        }
    }

    lucide.createIcons();
}

function updateExportButtons() {
    const exportButtons = document.getElementById('export-buttons');
    if (allResults.length > 0) {
        exportButtons.classList.remove('hidden');
    } else {
        exportButtons.classList.add('hidden');
    }
}

function updateDashboard() {
    // Calculate summary statistics
    const totalThreats = allResults.length;
    const uniqueIPs = new Set(allResults.map(r => r.ip)).size;
    const attackTypeCounts = {};
    const ipCounts = {};

    allResults.forEach(result => {
        attackTypeCounts[result.attack_type] = (attackTypeCounts[result.attack_type] || 0) + 1;
        ipCounts[result.ip] = (ipCounts[result.ip] || 0) + 1;
    });

    const topAttackers = Object.entries(ipCounts)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 10);

    // Update summary cards
    document.getElementById('total-threats').textContent = totalThreats.toLocaleString();
    document.getElementById('unique-ips').textContent = uniqueIPs.toLocaleString();
    document.getElementById('attack-types-count').textContent = Object.keys(attackTypeCounts).length;

    if (topAttackers.length > 0) {
        document.getElementById('top-attacker-ip').textContent = topAttackers[0][0];
        document.getElementById('top-attacker-count').textContent = `${topAttackers[0][1]} attempts`;
    } else {
        document.getElementById('top-attacker-ip').textContent = 'N/A';
        document.getElementById('top-attacker-count').textContent = '0 attempts';
    }

    // Update attack distribution
    const distributionContainer = document.getElementById('attack-distribution');
    distributionContainer.innerHTML = '';

    Object.entries(attackTypeCounts)
        .sort(([, a], [, b]) => b - a)
        .forEach(([type, count]) => {
            const percentage = ((count / totalThreats) * 100).toFixed(1);
            const div = document.createElement('div');
            div.className = 'flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg';
            div.innerHTML = `
                        <span class="font-medium text-gray-900 dark:text-white">${type}</span>
                        <div class="flex items-center space-x-2">
                            <span class="text-sm text-gray-500 dark:text-gray-400">${percentage}%</span>
                            <span class="text-lg font-semibold text-gray-900 dark:text-white">${count}</span>
                        </div>
                    `;
            distributionContainer.appendChild(div);
        });

    // Update top attackers
    const attackersContainer = document.getElementById('top-attackers-list');
    attackersContainer.innerHTML = '';

    topAttackers.forEach(([ip, count], index) => {
        const div = document.createElement('div');
        div.className = 'flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg';
        div.innerHTML = `
                    <div class="flex items-center space-x-3">
                        <div class="w-8 h-8 bg-red-100 dark:bg-red-900/20 rounded-full flex items-center justify-center">
                            <span class="text-sm font-medium text-red-600 dark:text-red-400">#${index + 1}</span>
                        </div>
                        <div>
                            <p class="font-mono text-sm text-gray-900 dark:text-white">${ip}</p>
                        </div>
                    </div>
                    <div class="text-right">
                        <p class="text-lg font-semibold text-gray-900 dark:text-white">${count}</p>
                        <p class="text-xs text-gray-500 dark:text-gray-400">attempts</p>
                    </div>
                `;
        attackersContainer.appendChild(div);
    });
}

function updateDataTable() {
    const tbody = document.getElementById('data-table-body');
    const countElement = document.getElementById('data-count');

    countElement.textContent = allResults.length.toLocaleString();
    tbody.innerHTML = '';

    allResults.slice(0, 100).forEach((entry, index) => {
        const row = document.createElement('tr');
        row.className = 'hover:bg-gray-50 dark:hover:bg-gray-700';

        const getMethodClass = (method) => {
            if (method === 'GET') return 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-300';
            if (method === 'POST') return 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-300';
            return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300';
        };

        const getStatusClass = (status) => {
            if (status >= 200 && status < 300) return 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-300';
            if (status >= 300 && status < 400) return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-300';
            if (status >= 400 && status < 500) return 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-300';
            if (status >= 500) return 'bg-purple-100 text-purple-800 dark:bg-purple-900/20 dark:text-purple-300';
            return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300';
        };

        row.innerHTML = `
                    <td class="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-900 dark:text-white">${entry.ip}</td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-300">${new Date(entry.timestamp).toLocaleString()}</td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                        <span class="px-2 py-1 rounded-full text-xs font-medium ${getMethodClass(entry.method)}">${entry.method}</span>
                    </td>
                    <td class="px-6 py-4 text-sm text-gray-900 dark:text-white max-w-xs">
                        <div class="truncate" title="${entry.path}">${entry.path}</div>
                    </td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                        <span class="px-2 py-1 rounded-full text-xs font-medium ${getStatusClass(entry.status)}">${entry.status}</span>
                    </td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">${entry.attack_type}</td>
                    <td class="px-6 py-4 text-sm text-gray-500 dark:text-gray-300 max-w-xs">
                        <div class="truncate" title="${entry.suspicion_reason}">${entry.suspicion_reason}</div>
                    </td>
                `;
        tbody.appendChild(row);
    });

    if (allResults.length > 100) {
        const row = document.createElement('tr');
        row.innerHTML = `
                    <td colspan="7" class="px-6 py-4 text-center text-sm text-gray-500 dark:text-gray-400">
                        Showing first 100 of ${allResults.length} results
                    </td>
                `;
        tbody.appendChild(row);
    }
}

function renderAttackCards() {
    const container = document.getElementById('attack-cards');
    container.innerHTML = '';

    ATTACK_TYPES.forEach(attackType => {
        const card = document.createElement('div');
        card.id = `card-${attackType.endpoint}`;
        card.className = 'bg-white dark:bg-gray-800 rounded-xl p-6 shadow-lg hover:shadow-xl transition-all duration-200 hover:-translate-y-1 border border-gray-200 dark:border-gray-700 flex flex-col h-full';

        const severityIcon = attackType.severity === 'high' ? 'alert-triangle' :
            attackType.severity === 'medium' ? 'shield' : 'info';

        const severityClass = attackType.severity === 'high' ? 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-300' :
            attackType.severity === 'medium' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-300' :
                'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-300';

        card.innerHTML = `
                    <div class="flex items-start justify-between mb-4">
                        <div class="flex items-center space-x-3">
                            <div class="p-2 rounded-lg" style="background-color: ${attackType.color}20">
                                <i data-lucide="${severityIcon}" class="w-6 h-6" style="color: ${attackType.color}"></i>
                            </div>
                            <div>
                                <h3 class="text-lg font-semibold text-gray-900 dark:text-white">
                                    ${attackType.name}
                                </h3>
                                <span class="inline-block px-2 py-1 rounded-full text-xs font-medium ${severityClass}">
                                    ${attackType.severity.toUpperCase()}
                                </span>
                            </div>
                        </div>
                        <div class="text-right">
                            <div class="text-2xl font-bold text-gray-900 dark:text-white threat-count">0</div>
                            <div class="text-xs text-gray-500 dark:text-gray-400">instances</div>
                        </div>
                    </div>

                    <p class="text-sm text-gray-600 dark:text-gray-300 mb-4">
                        ${attackType.description}
                    </p>

                    <div class="space-y-2 mt-auto">
                        <button class="scan-button w-full flex items-center justify-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded-lg transition-colors" onclick="handleScan(ATTACK_TYPES.find(t => t.endpoint === '${attackType.endpoint}'))">
                            <i data-lucide="play" class="w-4 h-4"></i>
                            <span>Scan</span>
                        </button>
                        
                        <button class="view-button w-full flex items-center justify-center space-x-2 px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded-lg transition-colors hidden" onclick="handleViewDetails('${attackType.name}')">
                            <i data-lucide="eye" class="w-4 h-4"></i>
                            <span>View Results (0)</span>
                        </button>
                        
                        <button class="w-full flex items-center justify-center space-x-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg transition-colors" onclick="handleViewFunction('${attackType.name}')">
                            <i data-lucide="code" class="w-4 h-4"></i>
                            <span>View Function</span>
                        </button>
                    </div>
                `;

        container.appendChild(card);
    });

    lucide.createIcons();
}

// Modal Functions
function handleViewDetails(attackType) {
    selectedAttackType = attackType;
    const results = scanResults[attackType] || [];

    document.getElementById('modal-title').textContent = `${attackType} - Detailed Results`;

    const modalContent = document.getElementById('modal-content');

    if (results.length === 0) {
        modalContent.innerHTML = '<p class="text-gray-500 dark:text-gray-400">No results found for this attack type.</p>';
    } else {
        const table = document.createElement('table');
        table.className = 'w-full min-w-[1000px] border-collapse';

        table.innerHTML = `
                    <thead class="bg-gray-50 dark:bg-gray-700">
                        <tr>
                            <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider border border-gray-200 dark:border-gray-600">IP</th>
                            <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider border border-gray-200 dark:border-gray-600">Timestamp</th>
                            <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider border border-gray-200 dark:border-gray-600">Method</th>
                            <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider border border-gray-200 dark:border-gray-600">Path</th>
                            <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider border border-gray-200 dark:border-gray-600">Status</th>
                            <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider border border-gray-200 dark:border-gray-600">Reason</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white dark:bg-gray-800">
                        ${results.slice(0, 50).map(entry => `
                            <tr class="hover:bg-gray-50 dark:hover:bg-gray-700">
                                <td class="px-4 py-2 text-sm font-mono text-gray-900 dark:text-white border border-gray-200 dark:border-gray-600">${entry.ip}</td>
                                <td class="px-4 py-2 text-sm text-gray-500 dark:text-gray-300 border border-gray-200 dark:border-gray-600">${new Date(entry.timestamp).toLocaleString()}</td>
                                <td class="px-4 py-2 text-sm text-gray-900 dark:text-white border border-gray-200 dark:border-gray-600">${entry.method}</td>
                                <td class="px-4 py-2 text-sm text-gray-900 dark:text-white border border-gray-200 dark:border-gray-600 max-w-xs">
                                    <div class="truncate" title="${entry.path}">${entry.path}</div>
                                </td>
                                <td class="px-4 py-2 text-sm text-gray-900 dark:text-white border border-gray-200 dark:border-gray-600">${entry.status}</td>
                                <td class="px-4 py-2 text-sm text-gray-500 dark:text-gray-300 border border-gray-200 dark:border-gray-600 max-w-xs">
                                    <div class="truncate" title="${entry.suspicion_reason}">${entry.suspicion_reason}</div>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                `;

        modalContent.innerHTML = '';
        modalContent.appendChild(table);

        if (results.length > 50) {
            const note = document.createElement('p');
            note.className = 'mt-4 text-sm text-gray-500 dark:text-gray-400 text-center';
            note.textContent = `Showing first 50 of ${results.length} results`;
            modalContent.appendChild(note);
        }
    }

    document.getElementById('details-modal').classList.remove('hidden');
}

function handleViewFunction(attackType) {
    const attackTypeConfig = ATTACK_TYPES.find(t => t.name === attackType);
    if (!attackTypeConfig) return;

    const detector = DETECTORS[attackTypeConfig.endpoint];
    if (!detector) return;

    document.getElementById('function-modal-title').textContent = `${attackType} - Detection Function`;
    document.getElementById('function-code').textContent = detector.toString();
    document.getElementById('function-modal').classList.remove('hidden');
}

// Event Listeners
document.addEventListener('DOMContentLoaded', function () {
    // Initialize theme
    initTheme();

    // Initialize Lucide icons
    lucide.createIcons();

    // Render attack cards
    renderAttackCards();

    // Theme toggle
    document.getElementById('theme-toggle').addEventListener('click', toggleTheme);

    // Tab navigation
    document.getElementById('tab-overview').addEventListener('click', () => setActiveView('overview'));
    document.getElementById('tab-dashboard').addEventListener('click', () => setActiveView('dashboard'));
    document.getElementById('tab-data').addEventListener('click', () => setActiveView('data'));

    // File upload
    const fileInput = document.getElementById('file-input');
    const fileUploadArea = document.getElementById('file-upload-area');
    const selectedFileDiv = document.getElementById('selected-file');
    const fileInfo = document.getElementById('file-info');
    const attackSection = document.getElementById('attack-section');

    fileInput.addEventListener('change', function (e) {
        const file = e.target.files[0];
        if (file) {
            selectedFile = file;
            fileInfo.textContent = `Selected: ${file.name} (${(file.size / 1024 / 1024).toFixed(2)} MB)`;
            selectedFileDiv.classList.remove('hidden');
            attackSection.classList.remove('hidden');
            addToast(`File "${file.name}" selected successfully`, 'success');
        }
    });

    // Drag and drop
    fileUploadArea.addEventListener('dragover', function (e) {
        e.preventDefault();
        fileUploadArea.classList.add('border-blue-400', 'bg-blue-50', 'dark:bg-blue-900/20');
    });

    fileUploadArea.addEventListener('dragleave', function (e) {
        e.preventDefault();
        fileUploadArea.classList.remove('border-blue-400', 'bg-blue-50', 'dark:bg-blue-900/20');
    });

    fileUploadArea.addEventListener('drop', function (e) {
        e.preventDefault();
        fileUploadArea.classList.remove('border-blue-400', 'bg-blue-50', 'dark:bg-blue-900/20');

        const files = e.dataTransfer.files;
        if (files.length > 0) {
            const file = files[0];
            selectedFile = file;
            fileInfo.textContent = `Selected: ${file.name} (${(file.size / 1024 / 1024).toFixed(2)} MB)`;
            selectedFileDiv.classList.remove('hidden');
            attackSection.classList.remove('hidden');
            addToast(`File "${file.name}" selected successfully`, 'success');
        }
    });

    // Demo load
    document.getElementById('load-demo').addEventListener('click', async function () {
        const button = this;
        const originalContent = button.innerHTML;

        button.disabled = true;
        button.innerHTML = '<div class="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div><span>Loading...</span>';

        try {
            addToast('Loading demo dataset...', 'info');

            const response = await fetch('https://raw.githubusercontent.com/Yadav-Aayansh/gramener-datasets/refs/heads/add-server-logs/server_logs.zip');

            if (!response.ok) {
                throw new Error(`Failed to fetch demo dataset: ${response.statusText}`);
            }

            const blob = await response.blob();
            const file = new File([blob], 'server_logs.zip', { type: 'application/zip' });

            selectedFile = file;
            fileInfo.textContent = `Selected: ${file.name} (${(file.size / 1024 / 1024).toFixed(2)} MB)`;
            selectedFileDiv.classList.remove('hidden');
            attackSection.classList.remove('hidden');

            addToast(`Demo dataset "${file.name}" loaded successfully!`, 'success');
        } catch (error) {
            console.error('Failed to load demo dataset:', error);
            addToast(`Failed to load demo dataset: ${error.message}`, 'error');
        } finally {
            button.disabled = false;
            button.innerHTML = originalContent;
            lucide.createIcons();
        }
    });

    // Run all scans
    document.getElementById('run-all-scans').addEventListener('click', handleRunAll);

    // Export buttons
    document.getElementById('export-csv').addEventListener('click', function () {
        if (allResults.length === 0) {
            addToast('No data to export', 'error');
            return;
        }

        const timestamp = new Date().toISOString().split('T')[0];
        const filename = `log-analysis-${timestamp}.csv`;
        const csvContent = exportToCSV(allResults);
        downloadFile(csvContent, filename, 'text/csv');
        addToast('Data exported as CSV', 'success');
    });

    document.getElementById('export-json').addEventListener('click', function () {
        if (allResults.length === 0) {
            addToast('No data to export', 'error');
            return;
        }

        const timestamp = new Date().toISOString().split('T')[0];
        const filename = `log-analysis-${timestamp}.json`;
        const jsonContent = exportToJSON(allResults);
        downloadFile(jsonContent, filename, 'application/json');
        addToast('Data exported as JSON', 'success');
    });

    // Modal close buttons
    document.getElementById('close-modal').addEventListener('click', function () {
        document.getElementById('details-modal').classList.add('hidden');
    });

    document.getElementById('close-function-modal').addEventListener('click', function () {
        document.getElementById('function-modal').classList.add('hidden');
    });

    // Close modals on background click
    document.getElementById('details-modal').addEventListener('click', function (e) {
        if (e.target === this) {
            this.classList.add('hidden');
        }
    });

    document.getElementById('function-modal').addEventListener('click', function (e) {
        if (e.target === this) {
            this.classList.add('hidden');
        }
    });
});

// Make functions globally available
window.handleScan = handleScan;
window.handleViewDetails = handleViewDetails;
window.handleViewFunction = handleViewFunction;
window.removeToast = removeToast;
window.ATTACK_TYPES = ATTACK_TYPES;