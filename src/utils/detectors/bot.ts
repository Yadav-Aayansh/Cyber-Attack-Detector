import { ParsedLogEntry } from '../logParser';

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

function classifyUserAgent(ua: string): string | null {
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

export function detectBots(entries: ParsedLogEntry[]): ParsedLogEntry[] {
  const bots = entries.filter(entry => {
    const botType = classifyUserAgent(entry.user_agent);
    return botType !== null;
  });

  return bots.map(entry => ({
    ...entry,
    suspicion_reason: classifyUserAgent(entry.user_agent) || 'Bot detected'
  }));
}