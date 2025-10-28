import * as fs from 'fs';
import * as path from 'path';

/**
 * Generate sample login data with normal and suspicious patterns
 */

// Sample IP addresses with their approximate locations
const ipLocations = {
  // New York, USA
  newYork: ['8.8.8.8', '8.8.4.4'],
  // London, UK
  london: ['81.2.69.142', '81.2.69.143'],
  // Tokyo, Japan
  tokyo: ['133.130.96.1', '133.130.96.2'],
  // Sydney, Australia
  sydney: ['1.1.1.1', '1.0.0.1'],
  // Mumbai, India
  mumbai: ['106.51.0.1', '106.51.0.2']
};

interface SampleLogin {
  userId: string;
  timestamp: string;
  ipAddress: string;
  success: boolean;
  userAgent?: string;
  sessionId?: string;
}

function randomChoice<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function generateSessionId(): string {
  return 'sess_' + Math.random().toString(36).substring(2, 15);
}

function generateNormalLogins(userId: string, count: number, startDate: Date): SampleLogin[] {
  const logins: SampleLogin[] = [];
  const baseIP = randomChoice(ipLocations.newYork);
  const userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';
  
  // Generate logins during typical hours (9 AM - 6 PM on weekdays)
  for (let i = 0; i < count; i++) {
    const date = new Date(startDate.getTime() + i * 24 * 60 * 60 * 1000); // Daily logins
    
    // Skip weekends
    if (date.getDay() === 0 || date.getDay() === 6) {
      continue;
    }
    
    // Set time to business hours (9-18)
    const hour = 9 + Math.floor(Math.random() * 9);
    date.setHours(hour, Math.floor(Math.random() * 60), 0, 0);
    
    logins.push({
      userId,
      timestamp: date.toISOString(),
      ipAddress: baseIP,
      success: true,
      userAgent,
      sessionId: generateSessionId()
    });
  }
  
  return logins;
}

function generateSuspiciousLogins(): SampleLogin[] {
  const logins: SampleLogin[] = [];
  const startDate = new Date('2024-01-01T00:00:00Z');
  
  // Scenario 1: User with impossible travel
  const user1 = 'user_001';
  logins.push({
    userId: user1,
    timestamp: new Date(startDate.getTime() + 0).toISOString(),
    ipAddress: ipLocations.newYork[0],
    success: true,
    userAgent: 'Mozilla/5.0',
    sessionId: generateSessionId()
  });
  
  // Impossible: Login from Tokyo 30 minutes later
  logins.push({
    userId: user1,
    timestamp: new Date(startDate.getTime() + 30 * 60 * 1000).toISOString(),
    ipAddress: ipLocations.tokyo[0],
    success: true,
    userAgent: 'Mozilla/5.0',
    sessionId: generateSessionId()
  });
  
  // Scenario 2: Brute force attack
  const user2 = 'user_002';
  const attackTime = new Date(startDate.getTime() + 2 * 24 * 60 * 60 * 1000);
  
  // Multiple failed attempts
  for (let i = 0; i < 10; i++) {
    logins.push({
      userId: user2,
      timestamp: new Date(attackTime.getTime() + i * 60 * 1000).toISOString(),
      ipAddress: ipLocations.mumbai[0],
      success: false,
      userAgent: 'Python/3.9',
      sessionId: generateSessionId()
    });
  }
  
  // Scenario 3: Unusual time login
  const user3 = 'user_003';
  // First, establish normal pattern (business hours)
  for (let i = 0; i < 15; i++) {
    const date = new Date(startDate.getTime() + i * 24 * 60 * 60 * 1000);
    date.setHours(10, 0, 0, 0);
    logins.push({
      userId: user3,
      timestamp: date.toISOString(),
      ipAddress: ipLocations.london[0],
      success: true,
      userAgent: 'Mozilla/5.0',
      sessionId: generateSessionId()
    });
  }
  
  // Then login at 3 AM (unusual)
  const unusualDate = new Date(startDate.getTime() + 16 * 24 * 60 * 60 * 1000);
  unusualDate.setHours(3, 0, 0, 0);
  logins.push({
    userId: user3,
    timestamp: unusualDate.toISOString(),
    ipAddress: ipLocations.london[0],
    success: true,
    userAgent: 'Mozilla/5.0',
    sessionId: generateSessionId()
  });
  
  return logins;
}

function generateMixedDataset(): SampleLogin[] {
  const logins: SampleLogin[] = [];
  const startDate = new Date('2024-01-01T00:00:00Z');
  
  // Generate normal logins for multiple users
  for (let i = 1; i <= 5; i++) {
    const normalLogins = generateNormalLogins(`user_${String(i).padStart(3, '0')}`, 30, startDate);
    logins.push(...normalLogins);
  }
  
  // Add suspicious patterns
  logins.push(...generateSuspiciousLogins());
  
  // Sort by timestamp
  logins.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  
  return logins;
}

function saveAsJSON(data: SampleLogin[], filename: string): void {
  const filepath = path.join(__dirname, filename);
  fs.writeFileSync(filepath, JSON.stringify(data, null, 2), 'utf-8');
  console.log(`Generated: ${filepath}`);
}

function saveAsCSV(data: SampleLogin[], filename: string): void {
  const headers = ['userId', 'timestamp', 'ipAddress', 'success', 'userAgent', 'sessionId'];
  const rows = data.map(login => [
    login.userId,
    login.timestamp,
    login.ipAddress,
    login.success,
    login.userAgent || '',
    login.sessionId || ''
  ]);
  
  const csvContent = [
    headers.join(','),
    ...rows.map(row => row.join(','))
  ].join('\n');
  
  const filepath = path.join(__dirname, filename);
  fs.writeFileSync(filepath, csvContent, 'utf-8');
  console.log(`Generated: ${filepath}`);
}

// Generate sample data
console.log('Generating sample login data...\n');

const mixedData = generateMixedDataset();

saveAsJSON(mixedData, 'logins.json');
saveAsCSV(mixedData, 'logins.csv');

console.log(`\nTotal logins generated: ${mixedData.length}`);
console.log('\nYou can now analyze these files using:');
console.log('  npm run analyze sample-data/logins.json');
console.log('  npm run analyze sample-data/logins.csv');

