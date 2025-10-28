# Quick Start Guide

This guide will help you get started with the Suspicious Login Detector in under 5 minutes.

## Prerequisites

- Node.js (v14 or higher)
- npm or yarn

## Installation

```bash
# Navigate to the project directory
cd suspicious-login-detector

# Install dependencies
npm install

# Build the project
npm run build
```

## Option 1: Try the Library

Create a file `test.ts`:

```typescript
import { SuspiciousLoginDetector } from './src/index';

async function main() {
  const detector = new SuspiciousLoginDetector();
  
  const loginAttempt = {
    userId: 'user_123',
    timestamp: new Date(),
    ipAddress: '8.8.8.8',
    success: true
  };
  
  const result = await detector.analyzeLogin(loginAttempt);
  
  console.log(`Risk Level: ${result.riskLevel}`);
  console.log(`Overall Risk: ${result.overallRisk}/100`);
  console.log('Recommendations:', result.recommendations);
}

main();
```

Run it:
```bash
npx ts-node test.ts
```

## Option 2: Try the API Server

1. Start the server:
```bash
npm run dev
```

2. In another terminal, test the API:
```bash
curl -X POST http://localhost:3000/api/login/check \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "user_123",
    "ipAddress": "8.8.8.8",
    "success": true
  }'
```

Or use the provided test script:
```bash
./examples/test-api.sh
```

## Option 3: Try the Log Analyzer

1. Generate sample data:
```bash
cd sample-data
npx ts-node generate-sample-data.ts
cd ..
```

2. Analyze the logs:
```bash
npm run analyze sample-data/logins.json
```

## Run Examples

See all features in action:
```bash
npx ts-node examples/library-usage.ts
```

## What's Next?

- Read the [README.md](README.md) for detailed documentation
- Customize the configuration in `src/utils/config.ts`
- Integrate into your application
- Set up persistence for user profiles
- Add webhooks for alerts

## Common Use Cases

### Detecting Impossible Travel
```typescript
// User logs in from New York
await detector.analyzeLogin({
  userId: 'alice',
  ipAddress: '8.8.8.8',
  timestamp: new Date('2024-01-01T10:00:00Z'),
  success: true
});

// User logs in from Tokyo 30 minutes later (impossible!)
await detector.analyzeLogin({
  userId: 'alice',
  ipAddress: '133.130.96.1',
  timestamp: new Date('2024-01-01T10:30:00Z'),
  success: true
});
```

### Detecting Brute Force
```typescript
// Multiple failed attempts
for (let i = 0; i < 10; i++) {
  await detector.analyzeLogin({
    userId: 'bob',
    ipAddress: '106.51.0.1',
    timestamp: new Date(Date.now() + i * 60000),
    success: false
  });
}
```

## Troubleshooting

**Issue**: Cannot find module
- Solution: Run `npm install` and `npm run build`

**Issue**: API server won't start
- Solution: Check if port 3000 is already in use
- Alternative: Set PORT environment variable: `PORT=3001 npm run dev`

**Issue**: IP geolocation not working
- Solution: The `geoip-lite` library uses a local database. Some IPs may not be in the database. Use well-known IPs for testing (8.8.8.8, 1.1.1.1, etc.)

## Support

For more help, check out:
- [Full Documentation](README.md)
- [Example Code](examples/)
- [Sample Data](sample-data/)

