/**
 * Suspicious Login Detector
 * 
 * A TypeScript/Node.js library and REST API for detecting suspicious login attempts
 * based on location changes, impossible travel, brute force detection, and unusual login times.
 */

// Export main detector class
export { SuspiciousLoginDetector } from './core/detector';

// Export log analyzer
export { default as LogAnalyzer } from './analyzer/logAnalyzer';

// Export types
export {
  LoginAttempt,
  GeoLocation,
  RiskFactors,
  RiskAssessment,
  UserProfile,
  DetectorConfig,
  AnalysisReport
} from './types';

// Export utilities
export {
  getLocationFromIP,
  calculateDistance,
  calculateTravelSpeed
} from './utils/geoLocation';

export {
  getTimeDifferenceInHours,
  getTimeDifferenceInMinutes,
  getHourOfDay,
  calculateTypicalLoginHours,
  isUnusualLoginTime,
  getFailedAttemptsInWindow
} from './utils/timeAnalysis';

export {
  defaultConfig,
  createConfig
} from './utils/config';

// Export API server
export { default as app } from './api/server';

