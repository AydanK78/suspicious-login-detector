/**
 * Represents a single login attempt
 */
export interface LoginAttempt {
  userId: string;
  timestamp: Date;
  ipAddress: string;
  success: boolean;
  userAgent?: string;
  sessionId?: string;
}

/**
 * Geographical location information
 */
export interface GeoLocation {
  country: string;
  region: string;
  city: string;
  latitude: number;
  longitude: number;
}

/**
 * Risk factors for a login attempt
 */
export interface RiskFactors {
  locationChange: number;
  impossibleTravel: number;
  bruteForce: number;
  unusualTime: number;
}

/**
 * Risk assessment result
 */
export interface RiskAssessment {
  userId: string;
  timestamp: Date;
  overallRisk: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  factors: RiskFactors;
  recommendations: string[];
  details: string[];
}

/**
 * User profile with login patterns
 */
export interface UserProfile {
  userId: string;
  loginHistory: LoginAttempt[];
  typicalLocations: GeoLocation[];
  typicalLoginHours: number[]; // Array of hours (0-23)
  lastSuccessfulLogin?: LoginAttempt;
  failedAttempts: LoginAttempt[];
}

/**
 * Configuration for detection algorithms
 */
export interface DetectorConfig {
  // Maximum realistic travel speed in km/h
  maxTravelSpeed: number;
  
  // Time window for brute force detection (in minutes)
  bruteForceWindow: number;
  
  // Number of failed attempts to trigger brute force alert
  bruteForceThreshold: number;
  
  // Distance threshold for location change alert (in km)
  locationChangeThreshold: number;
  
  // Risk score thresholds
  riskThresholds: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
}

/**
 * Log analysis report
 */
export interface AnalysisReport {
  totalLogins: number;
  suspiciousLogins: number;
  usersAnalyzed: number;
  highRiskUsers: string[];
  reportGeneratedAt: Date;
  detailedResults: RiskAssessment[];
}

