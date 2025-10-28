/**
 * Example: Using Suspicious Login Detector as a Library
 */

import { SuspiciousLoginDetector, LoginAttempt } from '../src/index';

async function runExamples() {
  console.log('Suspicious Login Detector - Library Usage Examples\n');
  console.log('='.repeat(60) + '\n');

  // Initialize detector
  const detector = new SuspiciousLoginDetector();

  // Example 1: Normal login
  console.log('Example 1: Normal Login');
  console.log('-'.repeat(60));
  
  const normalLogin: LoginAttempt = {
    userId: 'alice',
    timestamp: new Date('2024-01-15T10:00:00Z'),
    ipAddress: '8.8.8.8', // New York area
    success: true
  };

  const result1 = await detector.analyzeLogin(normalLogin);
  console.log(`User: ${result1.userId}`);
  console.log(`Risk Level: ${result1.riskLevel}`);
  console.log(`Overall Risk Score: ${result1.overallRisk}/100`);
  console.log(`Recommendations:`, result1.recommendations[0]);
  console.log();

  // Example 2: Same user, same location - should remain low risk
  console.log('Example 2: Same User, Same Location (Next Day)');
  console.log('-'.repeat(60));
  
  const normalLogin2: LoginAttempt = {
    userId: 'alice',
    timestamp: new Date('2024-01-16T10:00:00Z'),
    ipAddress: '8.8.8.8',
    success: true
  };

  const result2 = await detector.analyzeLogin(normalLogin2);
  console.log(`Risk Level: ${result2.riskLevel}`);
  console.log(`Overall Risk Score: ${result2.overallRisk}/100`);
  console.log();

  // Example 3: Impossible travel - suspicious!
  console.log('Example 3: Impossible Travel Detection');
  console.log('-'.repeat(60));
  
  const impossibleTravel: LoginAttempt = {
    userId: 'alice',
    timestamp: new Date('2024-01-16T10:30:00Z'), // 30 minutes later
    ipAddress: '133.130.96.1', // Tokyo, Japan
    success: true
  };

  const result3 = await detector.analyzeLogin(impossibleTravel);
  console.log(`Risk Level: ${result3.riskLevel}`);
  console.log(`Overall Risk Score: ${result3.overallRisk}/100`);
  console.log(`Risk Factors:`);
  console.log(`  - Location Change: ${result3.factors.locationChange}`);
  console.log(`  - Impossible Travel: ${result3.factors.impossibleTravel}`);
  console.log(`  - Brute Force: ${result3.factors.bruteForce}`);
  console.log(`  - Unusual Time: ${result3.factors.unusualTime}`);
  console.log(`Details:`, result3.details.join(', '));
  console.log(`Recommendations:`);
  result3.recommendations.forEach(rec => console.log(`  - ${rec}`));
  console.log();

  // Example 4: Brute force attack
  console.log('Example 4: Brute Force Attack Detection');
  console.log('-'.repeat(60));
  
  const attackTime = new Date('2024-01-17T14:00:00Z');
  
  // Simulate multiple failed login attempts
  for (let i = 0; i < 8; i++) {
    const failedAttempt: LoginAttempt = {
      userId: 'bob',
      timestamp: new Date(attackTime.getTime() + i * 60 * 1000), // 1 minute apart
      ipAddress: '106.51.0.1', // Mumbai
      success: false
    };
    await detector.analyzeLogin(failedAttempt);
  }
  
  // Now try a successful login
  const afterAttack: LoginAttempt = {
    userId: 'bob',
    timestamp: new Date(attackTime.getTime() + 10 * 60 * 1000),
    ipAddress: '106.51.0.1',
    success: true
  };
  
  const result4 = await detector.analyzeLogin(afterAttack);
  console.log(`Risk Level: ${result4.riskLevel}`);
  console.log(`Overall Risk Score: ${result4.overallRisk}/100`);
  console.log(`Brute Force Risk Factor: ${result4.factors.bruteForce}`);
  console.log(`Details:`, result4.details.join(', '));
  console.log();

  // Example 5: Batch analysis
  console.log('Example 5: Batch Analysis');
  console.log('-'.repeat(60));
  
  const batchLogins: LoginAttempt[] = [
    {
      userId: 'charlie',
      timestamp: new Date('2024-01-18T09:00:00Z'),
      ipAddress: '8.8.8.8',
      success: true
    },
    {
      userId: 'charlie',
      timestamp: new Date('2024-01-18T09:05:00Z'),
      ipAddress: '133.130.96.1', // Impossible travel
      success: true
    },
    {
      userId: 'david',
      timestamp: new Date('2024-01-18T10:00:00Z'),
      ipAddress: '1.1.1.1',
      success: true
    }
  ];
  
  const batchResults = await detector.analyzeMultiple(batchLogins);
  console.log(`Analyzed ${batchResults.length} login attempts`);
  batchResults.forEach((result, index) => {
    console.log(`  ${index + 1}. User: ${result.userId}, Risk: ${result.riskLevel} (${result.overallRisk}/100)`);
  });
  console.log();

  // Example 6: User profile analysis
  console.log('Example 6: User Profile Analysis');
  console.log('-'.repeat(60));
  
  const aliceProfile = detector.getUserProfileData('alice');
  if (aliceProfile) {
    console.log(`User: ${aliceProfile.userId}`);
    console.log(`Total Logins: ${aliceProfile.loginHistory.length}`);
    console.log(`Failed Attempts: ${aliceProfile.failedAttempts.length}`);
    console.log(`Typical Locations: ${aliceProfile.typicalLocations.length} known locations`);
    aliceProfile.typicalLocations.forEach(loc => {
      console.log(`  - ${loc.city}, ${loc.country}`);
    });
  }
  console.log();

  console.log('='.repeat(60));
  console.log('Examples completed!');
}

// Run examples
runExamples().catch(console.error);

