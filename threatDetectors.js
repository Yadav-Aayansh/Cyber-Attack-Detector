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

export { parseLogFile, DETECTORS, processLogData };