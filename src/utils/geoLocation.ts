import geoip from 'geoip-lite';
import { GeoLocation } from '../types';

/**
 * Get geographical location from IP address
 */
export function getLocationFromIP(ipAddress: string): GeoLocation | null {
  const geo = geoip.lookup(ipAddress);
  
  if (!geo) {
    return null;
  }
  
  return {
    country: geo.country,
    region: geo.region,
    city: geo.city || 'Unknown',
    latitude: geo.ll[0],
    longitude: geo.ll[1]
  };
}

/**
 * Calculate distance between two geographical points using Haversine formula
 * @returns Distance in kilometers
 */
export function calculateDistance(
  lat1: number,
  lon1: number,
  lat2: number,
  lon2: number
): number {
  const R = 6371; // Earth's radius in kilometers
  const dLat = toRadians(lat2 - lat1);
  const dLon = toRadians(lon2 - lon1);
  
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRadians(lat1)) *
      Math.cos(toRadians(lat2)) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);
  
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  const distance = R * c;
  
  return distance;
}

/**
 * Convert degrees to radians
 */
function toRadians(degrees: number): number {
  return degrees * (Math.PI / 180);
}

/**
 * Calculate speed required to travel between two locations
 * @returns Speed in km/h
 */
export function calculateTravelSpeed(
  location1: GeoLocation,
  location2: GeoLocation,
  timeInHours: number
): number {
  if (timeInHours === 0) {
    return Infinity;
  }
  
  const distance = calculateDistance(
    location1.latitude,
    location1.longitude,
    location2.latitude,
    location2.longitude
  );
  
  return distance / timeInHours;
}

