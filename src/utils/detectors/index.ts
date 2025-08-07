// Import all detectors
import { detectSqlInjection } from './sqlInjection';
import { detectPathTraversal } from './pathTraversal';
import { detectBots } from './bot';
import { detectLfiRfi } from './lfiRfi';
import { detectWpProbe } from './wpProbe';
import { detectBruteForce } from './bruteForce';
import { detectErrors } from './errors';
import { detectInternalIp } from './internalIp';

// Export all detectors
export {
  detectSqlInjection,
  detectPathTraversal,
  detectBots,
  detectLfiRfi,
  detectWpProbe,
  detectBruteForce,
  detectErrors,
  detectInternalIp,
};

// Detector mapping for easy access
export const DETECTORS = {
  'sql-injection': detectSqlInjection,
  'path-traversal': detectPathTraversal,
  'bots': detectBots,
  'lfi-rfi': detectLfiRfi,
  'wp-probe': detectWpProbe,
  'brute-force': detectBruteForce,
  'errors': detectErrors,
  'internal-ip': detectInternalIp,
} as const;

export type DetectorKey = keyof typeof DETECTORS;