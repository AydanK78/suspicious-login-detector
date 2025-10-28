# Getting Started with Suspicious Login Detector

Welcome! This guide will walk you through the complete setup and usage of the Suspicious Login Detector.

## Table of Contents

1. [Installation](#installation)
2. [Verification](#verification)
3. [Three Ways to Use](#three-ways-to-use)
4. [Your First Detection](#your-first-detection)
5. [Understanding Results](#understanding-results)
6. [Next Steps](#next-steps)

## Installation

The project is already set up! Dependencies are installed and the code is compiled.

To verify, run:
```bash
npm run build
```

If you need to reinstall:
```bash
npm install
npm run build
```

## Verification

Run the integration tests to verify everything works:

```bash
npx ts-node test-integration.ts
```

You should see:
```
✓ All 8 tests passed!
```

## Three Ways to Use

### 1. 📚 As a Library (Recommended for Integration)

Perfect for integrating into your existing application.

**Example:**
```typescript
import { SuspiciousLoginDetector } from './src/index';

const detector = new SuspiciousLoginDetector();

const result = await detector.analyzeLogin({
  userId: 'alice',
  ipAddress: '8.8.8.8',
  timestamp: new Date(),
  success: true
});

console.log(`Risk: ${result.riskLevel} (${result.overallRisk}/100)`);
```

**Try it:**
```bash
npx ts-node examples/library-usage.ts
```

### 2. 🌐 As a REST API (Recommended for Services)

Perfect for microservices or when you need a language-agnostic interface.

**Start the server:**
```bash
npm run dev
```

**Test it:**
```bash
# Check health
curl http://localhost:3000/health

# Analyze a login
curl -X POST http://localhost:3000/api/login/check \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "alice",
    "ipAddress": "8.8.8.8",
    "success": true
  }'
```

**Full API tests:**
```bash
# In another terminal (while server is running)
./examples/test-api.sh
```

### 3. 📊 As a Log Analyzer (Recommended for Forensics)

Perfect for analyzing historical data or security audits.

**Analyze existing logs:**
```bash
npm run analyze sample-data/logins.json
```

**Export results:**
```bash
npm run analyze sample-data/logins.json output/report.json
npm run analyze sample-data/logins.csv output/report.csv
```

## Your First Detection

Let's detect some suspicious activity! Create a file called `my-first-test.ts`:

```typescript
import { SuspiciousLoginDetector } from './src/index';

async function detectSuspiciousLogin() {
  const detector = new SuspiciousLoginDetector();
  
  // Normal login from New York
  console.log('1. Normal login from New York...');
  await detector.analyzeLogin({
    userId: 'bob',
    ipAddress: '8.8.8.8',
    timestamp: new Date('2024-01-15T10:00:00Z'),
    success: true
  });
  
  // Suspicious: Login from Tokyo 30 minutes later!
  console.log('2. Login from Tokyo 30 minutes later...');
  const result = await detector.analyzeLogin({
    userId: 'bob',
    ipAddress: '133.130.96.1',
    timestamp: new Date('2024-01-15T10:30:00Z'),
    success: true
  });
  
  console.log('\n🚨 DETECTION RESULTS:');
  console.log(`Risk Level: ${result.riskLevel}`);
  console.log(`Risk Score: ${result.overallRisk}/100`);
  console.log('\nRecommendations:');
  result.recommendations.forEach(r => console.log(`  - ${r}`));
  console.log('\nDetails:');
  result.details.forEach(d => console.log(`  - ${d}`));
}

detectSuspiciousLogin();
```

Run it:
```bash
npx ts-node my-first-test.ts
```

## Understanding Results

### Risk Assessment Structure

```typescript
{
  userId: "bob",
  timestamp: "2024-01-15T10:30:00Z",
  overallRisk: 75,              // 0-100 score
  riskLevel: "high",            // low, medium, high, critical
  factors: {
    locationChange: 40,          // New location detected
    impossibleTravel: 95,        // Unrealistic travel speed
    bruteForce: 0,               // No failed attempts
    unusualTime: 35              // Outside normal hours
  },
  recommendations: [
    "Send alert for impossible travel detection",
    "Require multi-factor authentication"
  ],
  details: [
    "Login from: Tokyo, JP",
    "Impossible travel detected (Risk: 95)"
  ]
}
```

### Risk Levels Explained

| Level | Score | Meaning | Action |
|-------|-------|---------|--------|
| **Low** | 0-29 | Normal behavior | Allow login |
| **Medium** | 30-49 | Slightly suspicious | Monitor user |
| **High** | 50-69 | Suspicious | Require 2FA |
| **Critical** | 70-100 | Highly suspicious | Block & alert |

### Risk Factors

1. **Location Change (Weight: 20%)**
   - Detects login from new city/country
   - Learns typical locations over time

2. **Impossible Travel (Weight: 40%)**
   - Highest weight factor
   - Flags physically impossible travel
   - Max speed: 900 km/h (commercial flight)

3. **Brute Force (Weight: 30%)**
   - Monitors failed login attempts
   - Default: 5+ failures in 30 minutes = high risk

4. **Unusual Time (Weight: 10%)**
   - Learns user's typical login hours
   - Requires 10+ successful logins for pattern

## Next Steps

### Customize Configuration

```typescript
import { SuspiciousLoginDetector } from './src/index';

const detector = new SuspiciousLoginDetector({
  maxTravelSpeed: 1000,         // More lenient
  bruteForceThreshold: 3,       // Stricter (3 instead of 5)
  bruteForceWindow: 15,         // Shorter window (15 min)
  riskThresholds: {
    low: 20,
    medium: 40,
    high: 60,
    critical: 80
  }
});
```

### Generate Test Data

```bash
cd sample-data
npx ts-node generate-sample-data.ts
cd ..
```

This creates:
- `sample-data/logins.json` - Test data with suspicious patterns
- `sample-data/logins.csv` - Same data in CSV format

### Integrate into Your App

**Express.js:**
```typescript
import express from 'express';
import { SuspiciousLoginDetector } from 'suspicious-login-detector';

const app = express();
const detector = new SuspiciousLoginDetector();

app.post('/login', async (req, res) => {
  // Your existing login logic
  const user = await authenticateUser(req.body);
  
  // Add security check
  const assessment = await detector.analyzeLogin({
    userId: user.id,
    ipAddress: req.ip,
    timestamp: new Date(),
    success: true
  });
  
  if (assessment.riskLevel === 'critical' || assessment.riskLevel === 'high') {
    // Require 2FA or block
    return res.status(403).json({
      message: 'Additional verification required',
      assessment
    });
  }
  
  // Allow login
  res.json({ success: true, token: generateToken(user) });
});
```

### Explore Examples

All examples are in the `examples/` directory:

```bash
# Comprehensive library examples
npx ts-node examples/library-usage.ts

# API testing (requires server running)
npm run dev  # Terminal 1
./examples/test-api.sh  # Terminal 2
```

### Read Full Documentation

- **README.md** - Complete documentation
- **PROJECT_SUMMARY.md** - Technical implementation details
- **QUICKSTART.md** - 5-minute quick reference

## Common Scenarios

### Scenario 1: User Traveling Legitimately

If users complain about false positives during travel:

```typescript
// Increase max travel speed
const detector = new SuspiciousLoginDetector({
  maxTravelSpeed: 1200  // Allow faster travel
});
```

### Scenario 2: VPN Users

VPNs can trigger location changes:

```typescript
// Decrease location change threshold
const detector = new SuspiciousLoginDetector({
  locationChangeThreshold: 500  // More lenient
});
```

### Scenario 3: Strict Security Requirements

For banking or high-security apps:

```typescript
const detector = new SuspiciousLoginDetector({
  bruteForceThreshold: 3,     // Stricter
  maxTravelSpeed: 800,         // Stricter
  riskThresholds: {
    low: 15,                   // Lower thresholds
    medium: 30,
    high: 50,
    critical: 70
  }
});
```

## Troubleshooting

### Problem: "Cannot find module"
```bash
npm install
npm run build
```

### Problem: Port 3000 already in use
```bash
PORT=3001 npm run dev
```

### Problem: IP geolocation not working
- `geoip-lite` has limited database
- Use well-known IPs for testing:
  - `8.8.8.8` (Google DNS, USA)
  - `1.1.1.1` (Cloudflare, Australia)
  - `133.130.96.1` (Japan)

## Support & Resources

- 📖 [Full Documentation](README.md)
- 🔬 [Run Integration Tests](test-integration.ts)
- 💡 [View Examples](examples/)
- 📊 [Sample Data](sample-data/)

## What's Next?

1. ✅ Run the integration tests
2. ✅ Try the examples
3. ✅ Analyze sample data
4. ✅ Start the API server
5. ✅ Integrate into your app

## Questions?

Check out:
- The comprehensive [README.md](README.md)
- The [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md) for implementation details
- Run `npx ts-node examples/library-usage.ts` for live examples

---

**You're all set! Start detecting suspicious logins! 🚀**

