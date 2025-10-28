/**
 * Integration Test - Verify all components work together
 */

import { SuspiciousLoginDetector, LoginAttempt } from './src/index';
import LogAnalyzer from './src/analyzer/logAnalyzer';
import * as fs from 'fs';

async function runIntegrationTests() {
  console.log('='.repeat(70));
  console.log('INTEGRATION TEST - Suspicious Login Detector');
  console.log('='.repeat(70));
  console.log();

  let passed = 0;
  let failed = 0;

  // Test 1: Core Detector
  console.log('Test 1: Core Detector Initialization');
  try {
    const detector = new SuspiciousLoginDetector();
    console.log('✓ Detector initialized successfully');
    passed++;
  } catch (error) {
    console.log('✗ Failed to initialize detector:', error);
    failed++;
  }
  console.log();

  // Test 2: Single Login Analysis
  console.log('Test 2: Single Login Analysis');
  try {
    const detector = new SuspiciousLoginDetector();
    const login: LoginAttempt = {
      userId: 'test_user',
      timestamp: new Date(),
      ipAddress: '8.8.8.8',
      success: true
    };
    const result = await detector.analyzeLogin(login);
    
    if (result.userId === 'test_user' && typeof result.overallRisk === 'number') {
      console.log('✓ Login analysis successful');
      console.log(`  Risk Level: ${result.riskLevel}, Score: ${result.overallRisk}`);
      passed++;
    } else {
      console.log('✗ Invalid result structure');
      failed++;
    }
  } catch (error) {
    console.log('✗ Login analysis failed:', error);
    failed++;
  }
  console.log();

  // Test 3: Impossible Travel Detection
  console.log('Test 3: Impossible Travel Detection');
  try {
    const detector = new SuspiciousLoginDetector();
    
    // First login from New York
    await detector.analyzeLogin({
      userId: 'traveler',
      timestamp: new Date('2024-01-01T10:00:00Z'),
      ipAddress: '8.8.8.8',
      success: true
    });
    
    // Second login from Tokyo 1 hour later (impossible!)
    const result = await detector.analyzeLogin({
      userId: 'traveler',
      timestamp: new Date('2024-01-01T11:00:00Z'),
      ipAddress: '133.130.96.1',
      success: true
    });
    
    if (result.factors.impossibleTravel > 50 || result.factors.locationChange > 0) {
      console.log('✓ Impossible travel detected');
      console.log(`  Impossible Travel Risk: ${result.factors.impossibleTravel}`);
      console.log(`  Location Change Risk: ${result.factors.locationChange}`);
      passed++;
    } else {
      console.log('✗ Failed to detect impossible travel');
      failed++;
    }
  } catch (error) {
    console.log('✗ Impossible travel test failed:', error);
    failed++;
  }
  console.log();

  // Test 4: Brute Force Detection
  console.log('Test 4: Brute Force Detection');
  try {
    const detector = new SuspiciousLoginDetector();
    const baseTime = new Date();
    
    // Simulate 8 failed attempts
    for (let i = 0; i < 8; i++) {
      await detector.analyzeLogin({
        userId: 'attacked_user',
        timestamp: new Date(baseTime.getTime() + i * 60000),
        ipAddress: '1.1.1.1',
        success: false
      });
    }
    
    // Check detection on successful login
    const result = await detector.analyzeLogin({
      userId: 'attacked_user',
      timestamp: new Date(baseTime.getTime() + 10 * 60000),
      ipAddress: '1.1.1.1',
      success: true
    });
    
    if (result.factors.bruteForce > 60) {
      console.log('✓ Brute force attack detected');
      console.log(`  Brute Force Risk: ${result.factors.bruteForce}`);
      passed++;
    } else {
      console.log('✗ Failed to detect brute force attack');
      console.log(`  Brute Force Risk: ${result.factors.bruteForce}`);
      failed++;
    }
  } catch (error) {
    console.log('✗ Brute force test failed:', error);
    failed++;
  }
  console.log();

  // Test 5: Batch Analysis
  console.log('Test 5: Batch Analysis');
  try {
    const detector = new SuspiciousLoginDetector();
    const logins: LoginAttempt[] = [
      {
        userId: 'batch_user_1',
        timestamp: new Date(),
        ipAddress: '8.8.8.8',
        success: true
      },
      {
        userId: 'batch_user_2',
        timestamp: new Date(),
        ipAddress: '1.1.1.1',
        success: true
      }
    ];
    
    const results = await detector.analyzeMultiple(logins);
    
    if (results.length === 2) {
      console.log('✓ Batch analysis successful');
      console.log(`  Analyzed ${results.length} login attempts`);
      passed++;
    } else {
      console.log('✗ Batch analysis returned wrong number of results');
      failed++;
    }
  } catch (error) {
    console.log('✗ Batch analysis failed:', error);
    failed++;
  }
  console.log();

  // Test 6: User Profile Retrieval
  console.log('Test 6: User Profile Retrieval');
  try {
    const detector = new SuspiciousLoginDetector();
    
    await detector.analyzeLogin({
      userId: 'profile_user',
      timestamp: new Date(),
      ipAddress: '8.8.8.8',
      success: true
    });
    
    const profile = await detector.getUserProfileData('profile_user');
    
    if (profile && profile.userId === 'profile_user' && profile.loginHistory.length === 1) {
      console.log('✓ User profile retrieval successful');
      console.log(`  Login history: ${profile.loginHistory.length} entries`);
      passed++;
    } else {
      console.log('✗ Failed to retrieve user profile');
      failed++;
    }
  } catch (error) {
    console.log('✗ User profile test failed:', error);
    failed++;
  }
  console.log();

  // Test 7: Log Analyzer with Sample Data
  console.log('Test 7: Log Analyzer with Sample Data');
  try {
    if (fs.existsSync('sample-data/logins.json')) {
      const analyzer = new LogAnalyzer();
      const report = await analyzer.analyzeFromJSON('sample-data/logins.json');
      
      if (report.totalLogins > 0 && report.usersAnalyzed > 0) {
        console.log('✓ Log analysis successful');
        console.log(`  Total Logins: ${report.totalLogins}`);
        console.log(`  Users Analyzed: ${report.usersAnalyzed}`);
        console.log(`  Suspicious Logins: ${report.suspiciousLogins}`);
        passed++;
      } else {
        console.log('✗ Log analysis returned empty results');
        failed++;
      }
    } else {
      console.log('⊘ Sample data not found, skipping test');
    }
  } catch (error) {
    console.log('✗ Log analyzer test failed:', error);
    failed++;
  }
  console.log();

  // Test 8: Custom Configuration
  console.log('Test 8: Custom Configuration');
  try {
    const detector = new SuspiciousLoginDetector({
      maxTravelSpeed: 1000,
      bruteForceThreshold: 3,
      riskThresholds: {
        low: 25,
        medium: 45,
        high: 65,
        critical: 85
      }
    });
    
    const result = await detector.analyzeLogin({
      userId: 'config_test',
      timestamp: new Date(),
      ipAddress: '8.8.8.8',
      success: true
    });
    
    if (result.userId === 'config_test') {
      console.log('✓ Custom configuration successful');
      passed++;
    } else {
      console.log('✗ Custom configuration failed');
      failed++;
    }
  } catch (error) {
    console.log('✗ Custom configuration test failed:', error);
    failed++;
  }
  console.log();

  // Summary
  console.log('='.repeat(70));
  console.log('TEST SUMMARY');
  console.log('='.repeat(70));
  console.log(`Total Tests: ${passed + failed}`);
  console.log(`Passed: ${passed} ✓`);
  console.log(`Failed: ${failed} ✗`);
  console.log(`Success Rate: ${((passed / (passed + failed)) * 100).toFixed(1)}%`);
  console.log('='.repeat(70));
  
  if (failed === 0) {
    console.log('\n🎉 All tests passed! The Suspicious Login Detector is working correctly.');
  } else {
    console.log('\n⚠️  Some tests failed. Please review the errors above.');
  }
  
  process.exit(failed > 0 ? 1 : 0);
}

// Run tests
runIntegrationTests().catch(error => {
  console.error('Fatal error running tests:', error);
  process.exit(1);
});

