import {
  LoginAttempt,
  RiskAssessment,
  UserProfile,
  DetectorConfig,
  RiskFactors,
  GeoLocation
} from '../types';
import {
  getLocationFromIP,
  calculateTravelSpeed
} from '../utils/geoLocation';
import {
  getTimeDifferenceInHours,
  calculateTypicalLoginHours,
  isUnusualLoginTime,
  getFailedAttemptsInWindow
} from '../utils/timeAnalysis';
import { defaultConfig } from '../utils/config';
import { getDatabase } from '../database/database';

/**
 * Main suspicious login detector class
 */
export class SuspiciousLoginDetector {
  private config: DetectorConfig;
  private db: ReturnType<typeof getDatabase>;

  constructor(config?: Partial<DetectorConfig>) {
    this.config = config
      ? { ...defaultConfig, ...config }
      : defaultConfig;
    this.db = getDatabase();
  }

  /**
   * Analyze a single login attempt
   */
  async analyzeLogin(attempt: LoginAttempt): Promise<RiskAssessment> {
    // Save login attempt to database
    await this.db.saveLoginAttempt(attempt);
    
    // Get or create user profile
    let profile = await this.db.getUserProfile(attempt.userId);
    if (!profile) {
      profile = {
        userId: attempt.userId,
        loginHistory: [],
        typicalLocations: [],
        typicalLoginHours: [],
        failedAttempts: []
      };
    }

    // Update profile with current attempt
    profile.loginHistory.push(attempt);
    if (!attempt.success) {
      profile.failedAttempts.push(attempt);
    } else {
      profile.lastSuccessfulLogin = attempt;
    }

    // Calculate risk factors
    const factors = this.calculateRiskFactors(attempt, profile);
    
    // Calculate overall risk score
    const overallRisk = this.calculateOverallRisk(factors);
    
    // Determine risk level
    const riskLevel = this.determineRiskLevel(overallRisk);
    
    // Generate recommendations and details
    const recommendations = this.generateRecommendations(factors, riskLevel);
    const details = this.generateDetails(attempt, profile, factors);

    const assessment: RiskAssessment = {
      userId: attempt.userId,
      timestamp: attempt.timestamp,
      overallRisk,
      riskLevel,
      factors,
      recommendations,
      details
    };

    // Save risk assessment to database
    await this.db.saveRiskAssessment(assessment);
    
    // Save updated profile to database
    await this.db.saveUserProfile(profile);

    return assessment;
  }

  /**
   * Analyze multiple login attempts
   */
  async analyzeMultiple(attempts: LoginAttempt[]): Promise<RiskAssessment[]> {
    const results: RiskAssessment[] = [];
    
    for (const attempt of attempts) {
      const assessment = await this.analyzeLogin(attempt);
      results.push(assessment);
    }
    
    return results;
  }

  /**
   * Get user profile from database
   */
  async getUserProfile(userId: string): Promise<UserProfile | null> {
    return await this.db.getUserProfile(userId);
  }

  /**
   * Calculate risk factors for a login attempt
   */
  private calculateRiskFactors(
    attempt: LoginAttempt,
    profile: UserProfile
  ): RiskFactors {
    return {
      locationChange: this.calculateLocationChangeRisk(attempt, profile),
      impossibleTravel: this.calculateImpossibleTravelRisk(attempt, profile),
      bruteForce: this.calculateBruteForceRisk(attempt, profile),
      unusualTime: this.calculateUnusualTimeRisk(attempt, profile)
    };
  }

  /**
   * Calculate location change risk
   */
  private calculateLocationChangeRisk(
    attempt: LoginAttempt,
    profile: UserProfile
  ): number {
    const currentLocation = getLocationFromIP(attempt.ipAddress);
    
    if (!currentLocation) {
      return 0; // Cannot determine location
    }

    // First login from this user
    if (profile.loginHistory.length === 0) {
      profile.typicalLocations.push(currentLocation);
      return 0;
    }

    // Check if location is in typical locations
    const isTypicalLocation = profile.typicalLocations.some(loc => 
      loc.country === currentLocation.country &&
      loc.city === currentLocation.city
    );

    if (isTypicalLocation) {
      return 0;
    }

    // New location - add to typical locations and return moderate risk
    profile.typicalLocations.push(currentLocation);
    return 40;
  }

  /**
   * Calculate impossible travel risk
   */
  private calculateImpossibleTravelRisk(
    attempt: LoginAttempt,
    profile: UserProfile
  ): number {
    if (!profile.lastSuccessfulLogin) {
      return 0;
    }

    const currentLocation = getLocationFromIP(attempt.ipAddress);
    const previousLocation = getLocationFromIP(profile.lastSuccessfulLogin.ipAddress);

    if (!currentLocation || !previousLocation) {
      return 0;
    }

    // Same location - no risk
    if (currentLocation.city === previousLocation.city &&
        currentLocation.country === previousLocation.country) {
      return 0;
    }

    const timeDiff = getTimeDifferenceInHours(
      profile.lastSuccessfulLogin.timestamp,
      attempt.timestamp
    );

    const requiredSpeed = calculateTravelSpeed(
      previousLocation,
      currentLocation,
      timeDiff
    );

    // If required speed exceeds maximum realistic speed, it's suspicious
    if (requiredSpeed > this.config.maxTravelSpeed) {
      // Scale risk based on how much the speed exceeds the limit
      const speedRatio = requiredSpeed / this.config.maxTravelSpeed;
      return Math.min(100, 60 + (speedRatio - 1) * 40);
    }

    // Possible but fast travel
    if (requiredSpeed > this.config.maxTravelSpeed * 0.7) {
      return 30;
    }

    return 0;
  }

  /**
   * Calculate brute force attack risk
   */
  private calculateBruteForceRisk(
    attempt: LoginAttempt,
    profile: UserProfile
  ): number {
    const recentFailures = getFailedAttemptsInWindow(
      profile.failedAttempts,
      attempt.timestamp,
      this.config.bruteForceWindow
    );

    const failureCount = recentFailures.length;

    if (failureCount >= this.config.bruteForceThreshold) {
      // Scale risk based on number of failed attempts
      const ratio = failureCount / this.config.bruteForceThreshold;
      return Math.min(100, 70 + (ratio - 1) * 30);
    }

    if (failureCount >= this.config.bruteForceThreshold * 0.7) {
      return 40;
    }

    return 0;
  }

  /**
   * Calculate unusual time risk
   */
  private calculateUnusualTimeRisk(
    attempt: LoginAttempt,
    profile: UserProfile
  ): number {
    // Need at least 10 successful logins to establish pattern
    const successfulLogins = profile.loginHistory.filter(l => l.success);
    
    if (successfulLogins.length < 10) {
      return 0;
    }

    const typicalHours = calculateTypicalLoginHours(successfulLogins);
    profile.typicalLoginHours = typicalHours;

    if (isUnusualLoginTime(attempt.timestamp, typicalHours)) {
      return 35;
    }

    return 0;
  }

  /**
   * Calculate overall risk score from individual factors
   */
  private calculateOverallRisk(factors: RiskFactors): number {
    // Weighted average of risk factors
    const weights = {
      locationChange: 0.2,
      impossibleTravel: 0.4,
      bruteForce: 0.3,
      unusualTime: 0.1
    };

    const score =
      factors.locationChange * weights.locationChange +
      factors.impossibleTravel * weights.impossibleTravel +
      factors.bruteForce * weights.bruteForce +
      factors.unusualTime * weights.unusualTime;

    return Math.round(score);
  }

  /**
   * Determine risk level from score
   */
  private determineRiskLevel(
    score: number
  ): 'low' | 'medium' | 'high' | 'critical' {
    const thresholds = this.config.riskThresholds;

    if (score >= thresholds.critical) return 'critical';
    if (score >= thresholds.high) return 'high';
    if (score >= thresholds.medium) return 'medium';
    return 'low';
  }

  /**
   * Generate recommendations based on risk assessment
   */
  private generateRecommendations(
    factors: RiskFactors,
    riskLevel: string
  ): string[] {
    const recommendations: string[] = [];

    if (riskLevel === 'critical' || riskLevel === 'high') {
      recommendations.push('Block login attempt and require additional verification');
    }

    if (factors.impossibleTravel > 50) {
      recommendations.push('Send alert for impossible travel detection');
      recommendations.push('Require multi-factor authentication');
    }

    if (factors.bruteForce > 50) {
      recommendations.push('Implement temporary account lockout');
      recommendations.push('Alert user of potential brute force attack');
    }

    if (factors.locationChange > 30) {
      recommendations.push('Send notification to user about new location login');
    }

    if (factors.unusualTime > 30) {
      recommendations.push('Consider requiring additional verification for unusual login times');
    }

    if (riskLevel === 'medium') {
      recommendations.push('Monitor this user for additional suspicious activity');
    }

    if (recommendations.length === 0) {
      recommendations.push('Login appears legitimate - allow access');
    }

    return recommendations;
  }

  /**
   * Generate detailed explanation of risk factors
   */
  private generateDetails(
    attempt: LoginAttempt,
    profile: UserProfile,
    factors: RiskFactors
  ): string[] {
    const details: string[] = [];

    const currentLocation = getLocationFromIP(attempt.ipAddress);
    if (currentLocation) {
      details.push(`Login from: ${currentLocation.city}, ${currentLocation.country}`);
    }

    if (factors.locationChange > 0) {
      details.push(`New location detected (Risk: ${factors.locationChange})`);
    }

    if (factors.impossibleTravel > 0) {
      details.push(`Impossible travel detected (Risk: ${factors.impossibleTravel})`);
      if (profile.lastSuccessfulLogin) {
        const prevLocation = getLocationFromIP(profile.lastSuccessfulLogin.ipAddress);
        if (prevLocation) {
          details.push(
            `Previous login from: ${prevLocation.city}, ${prevLocation.country}`
          );
        }
      }
    }

    if (factors.bruteForce > 0) {
      const recentFailures = getFailedAttemptsInWindow(
        profile.failedAttempts,
        attempt.timestamp,
        this.config.bruteForceWindow
      );
      details.push(
        `${recentFailures.length} failed login attempts in last ${this.config.bruteForceWindow} minutes (Risk: ${factors.bruteForce})`
      );
    }

    if (factors.unusualTime > 0) {
      details.push(`Login at unusual time (Risk: ${factors.unusualTime})`);
    }

    return details;
  }

  /**
   * Get user profile data from database
   */
  async getUserProfileData(userId: string): Promise<UserProfile | null> {
    return await this.db.getUserProfile(userId);
  }

  /**
   * Get dashboard statistics
   */
  async getDashboardStats(): Promise<any> {
    return await this.db.getDashboardStats();
  }

  /**
   * Get recent risk assessments
   */
  async getRecentRiskAssessments(limit: number = 50): Promise<RiskAssessment[]> {
    return await this.db.getRiskAssessments(undefined, limit);
  }
}

