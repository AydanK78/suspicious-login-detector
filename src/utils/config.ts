import { DetectorConfig } from '../types';

/**
 * Default configuration for the suspicious login detector
 */
export const defaultConfig: DetectorConfig = {
  // Maximum realistic travel speed: 900 km/h (average commercial flight speed)
  maxTravelSpeed: 900,
  
  // Time window for brute force detection: 30 minutes
  bruteForceWindow: 30,
  
  // Number of failed attempts to trigger brute force alert: 5
  bruteForceThreshold: 5,
  
  // Distance threshold for location change alert: 100 km
  locationChangeThreshold: 100,
  
  // Risk score thresholds
  riskThresholds: {
    low: 30,
    medium: 50,
    high: 70,
    critical: 85
  }
};

/**
 * Create a custom configuration by merging with defaults
 */
export function createConfig(customConfig: Partial<DetectorConfig>): DetectorConfig {
  return {
    ...defaultConfig,
    ...customConfig,
    riskThresholds: {
      ...defaultConfig.riskThresholds,
      ...customConfig.riskThresholds
    }
  };
}

