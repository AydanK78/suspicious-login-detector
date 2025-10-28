import { differenceInMinutes, differenceInHours, getHours } from 'date-fns';
import { LoginAttempt } from '../types';

/**
 * Calculate time difference between two dates in hours
 */
export function getTimeDifferenceInHours(date1: Date, date2: Date): number {
  return Math.abs(differenceInHours(date1, date2));
}

/**
 * Calculate time difference between two dates in minutes
 */
export function getTimeDifferenceInMinutes(date1: Date, date2: Date): number {
  return Math.abs(differenceInMinutes(date1, date2));
}

/**
 * Get the hour of day (0-23) from a date
 */
export function getHourOfDay(date: Date): number {
  return getHours(date);
}

/**
 * Calculate typical login hours for a user based on history
 */
export function calculateTypicalLoginHours(loginHistory: LoginAttempt[]): number[] {
  const hourCounts: { [hour: number]: number } = {};
  
  // Count logins per hour
  loginHistory.forEach(login => {
    const hour = getHourOfDay(login.timestamp);
    hourCounts[hour] = (hourCounts[hour] || 0) + 1;
  });
  
  // Find hours with significant activity (more than 10% of total logins)
  const totalLogins = loginHistory.length;
  const threshold = totalLogins * 0.1;
  
  const typicalHours: number[] = [];
  for (let hour = 0; hour < 24; hour++) {
    if (hourCounts[hour] >= threshold) {
      typicalHours.push(hour);
    }
  }
  
  // If no hours meet the threshold, include all hours with any activity
  if (typicalHours.length === 0) {
    return Object.keys(hourCounts).map(h => parseInt(h));
  }
  
  return typicalHours;
}

/**
 * Check if a login hour is unusual for the user
 */
export function isUnusualLoginTime(
  loginTime: Date,
  typicalHours: number[]
): boolean {
  if (typicalHours.length === 0) {
    return false; // Not enough data to determine
  }
  
  const hour = getHourOfDay(loginTime);
  return !typicalHours.includes(hour);
}

/**
 * Get failed login attempts within a time window
 */
export function getFailedAttemptsInWindow(
  attempts: LoginAttempt[],
  currentTime: Date,
  windowMinutes: number
): LoginAttempt[] {
  return attempts.filter(attempt => {
    if (attempt.success) return false;
    
    const timeDiff = getTimeDifferenceInMinutes(attempt.timestamp, currentTime);
    return timeDiff <= windowMinutes;
  });
}

