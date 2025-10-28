# Suspicious Login Detector

A TypeScript/Node.js library and REST API for detecting suspicious login attempts based on multiple risk factors including location changes, impossible travel, brute force detection, and unusual login times.

## Features

- **Location Change Detection**: Tracks and flags logins from new geographical locations
- **Impossible Travel Detection**: Identifies logins that would require unrealistic travel speeds
- **Brute Force Detection**: Monitors failed login attempts within configurable time windows
- **Unusual Time Detection**: Analyzes login patterns and detects anomalies in user behavior
- **REST API**: Full-featured API for real-time login analysis
- **Log Analyzer**: Command-line tool for analyzing historical login data
- **Library/Package**: Clean API for integration into your own applications

## Installation

```bash
# Clone the repository
cd suspicious-login-detector

# Install dependencies
npm install

# Build the project
npm run build
```

## Quick Start

### 1. As a Library

```typescript
import { SuspiciousLoginDetector } from 'suspicious-login-detector';

const detector = new SuspiciousLoginDetector();

const loginAttempt = {
  userId: 'user_123',
  timestamp: new Date(),
  ipAddress: '8.8.8.8',
  success: true
};

const assessment = await detector.analyzeLogin(loginAttempt);

console.log(`Risk Level: ${assessment.riskLevel}`);
console.log(`Overall Risk Score: ${assessment.overallRisk}`);
console.log('Recommendations:', assessment.recommendations);
```

### 2. As a REST API

Start the server:

```bash
npm run dev
```

The API will be available at `http://localhost:3000`

#### API Endpoints

**Check a single login:**
```bash
curl -X POST http://localhost:3000/api/login/check \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "user_123",
    "ipAddress": "8.8.8.8",
    "success": true,
    "timestamp": "2024-01-15T10:30:00Z"
  }'
```

**Batch analysis:**
```bash
curl -X POST http://localhost:3000/api/login/batch \
  -H "Content-Type: application/json" \
  -d '{
    "attempts": [
      {"userId": "user_123", "ipAddress": "8.8.8.8", "success": true},
      {"userId": "user_456", "ipAddress": "1.1.1.1", "success": false}
    ]
  }'
```

**Get user login history:**
```bash
curl http://localhost:3000/api/user/user_123/history
```

**Get user risk profile:**
```bash
curl http://localhost:3000/api/user/user_123/risk-profile
```

### 3. As a Log Analyzer

Analyze historical login data from JSON or CSV files:

```bash
# Analyze JSON file
npm run analyze sample-data/logins.json

# Analyze and export results
npm run analyze sample-data/logins.json output/report.json
npm run analyze sample-data/logins.csv output/report.csv
```

## Configuration

Customize the detector behavior with configuration options:

```typescript
import { SuspiciousLoginDetector, createConfig } from 'suspicious-login-detector';

const customConfig = createConfig({
  maxTravelSpeed: 900,           // km/h
  bruteForceWindow: 30,           // minutes
  bruteForceThreshold: 5,         // failed attempts
  locationChangeThreshold: 100,   // km
  riskThresholds: {
    low: 30,
    medium: 50,
    high: 70,
    critical: 85
  }
});

const detector = new SuspiciousLoginDetector(customConfig);
```

## Risk Assessment

The detector analyzes four main risk factors:

1. **Location Change** (Weight: 20%)
   - Detects logins from new locations
   - Tracks typical user locations

2. **Impossible Travel** (Weight: 40%)
   - Calculates if travel between locations is physically possible
   - Flags logins requiring speeds exceeding realistic limits

3. **Brute Force** (Weight: 30%)
   - Monitors failed login attempts
   - Detects potential credential stuffing attacks

4. **Unusual Time** (Weight: 10%)
   - Learns typical login patterns
   - Flags logins at unusual times

### Risk Levels

- **Low** (0-29): Normal login behavior
- **Medium** (30-49): Slightly suspicious, monitor
- **High** (50-69): Suspicious, require additional verification
- **Critical** (70-100): Highly suspicious, block and alert

## Sample Data

Generate sample data for testing:

```bash
cd sample-data
npx ts-node generate-sample-data.ts
```

This creates `logins.json` and `logins.csv` with both normal and suspicious login patterns.

## Data Format

### Login Attempt Format

**JSON:**
```json
{
  "userId": "user_123",
  "timestamp": "2024-01-15T10:30:00Z",
  "ipAddress": "8.8.8.8",
  "success": true,
  "userAgent": "Mozilla/5.0...",
  "sessionId": "sess_abc123"
}
```

**CSV:**
```csv
userId,timestamp,ipAddress,success,userAgent,sessionId
user_123,2024-01-15T10:30:00Z,8.8.8.8,true,Mozilla/5.0...,sess_abc123
```

### Risk Assessment Response

```json
{
  "userId": "user_123",
  "timestamp": "2024-01-15T10:30:00Z",
  "overallRisk": 75,
  "riskLevel": "high",
  "factors": {
    "locationChange": 40,
    "impossibleTravel": 95,
    "bruteForce": 0,
    "unusualTime": 35
  },
  "recommendations": [
    "Send alert for impossible travel detection",
    "Require multi-factor authentication",
    "Send notification to user about new location login"
  ],
  "details": [
    "Login from: Tokyo, JP",
    "Impossible travel detected (Risk: 95)",
    "Previous login from: New York, US"
  ]
}
```

## Project Structure

```
suspicious-login-detector/
├── src/
│   ├── core/
│   │   └── detector.ts          # Main detection engine
│   ├── api/
│   │   └── server.ts            # Express REST API
│   ├── analyzer/
│   │   └── logAnalyzer.ts       # Log file analyzer
│   ├── utils/
│   │   ├── geoLocation.ts       # IP geolocation utilities
│   │   ├── timeAnalysis.ts      # Time-based analysis
│   │   └── config.ts            # Configuration
│   ├── types/
│   │   └── index.ts             # TypeScript interfaces
│   └── index.ts                 # Library exports
├── sample-data/
│   └── generate-sample-data.ts  # Sample data generator
├── package.json
├── tsconfig.json
└── README.md
```

## Use Cases

1. **E-commerce Platforms**: Protect user accounts from unauthorized access
2. **Banking Applications**: Detect fraudulent login attempts
3. **SaaS Products**: Monitor suspicious access patterns
4. **Security Analytics**: Analyze historical login data for threats
5. **Compliance**: Generate audit reports for security reviews

## Advanced Usage

### Batch Processing

```typescript
const loginAttempts = [
  { userId: 'user_1', ipAddress: '8.8.8.8', success: true, timestamp: new Date() },
  { userId: 'user_2', ipAddress: '1.1.1.1', success: false, timestamp: new Date() }
];

const assessments = await detector.analyzeMultiple(loginAttempts);
```

### User Profile Analysis

```typescript
const profile = detector.getUserProfileData('user_123');

console.log('Typical Locations:', profile.typicalLocations);
console.log('Typical Login Hours:', profile.typicalLoginHours);
console.log('Total Logins:', profile.loginHistory.length);
```

### Custom Risk Thresholds

```typescript
const detector = new SuspiciousLoginDetector({
  riskThresholds: {
    low: 20,
    medium: 40,
    high: 60,
    critical: 80
  }
});
```

## Development

```bash
# Install dependencies
npm install

# Build TypeScript
npm run build

# Run development server
npm run dev

# Run analyzer
npm run analyze sample-data/logins.json
```

## Dependencies

- **express**: REST API framework
- **geoip-lite**: IP geolocation lookup
- **date-fns**: Date/time manipulation
- **typescript**: Type safety and development

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Security Considerations

- This library uses IP geolocation which may not always be 100% accurate
- Risk scores are probabilistic and should be used as part of a broader security strategy
- Always implement additional authentication factors for high-risk scenarios
- Store user login history securely and comply with data privacy regulations

## Roadmap

- [ ] Add machine learning models for enhanced detection
- [ ] Support for additional data sources (device fingerprinting, etc.)
- [ ] Dashboard for visualization
- [ ] Database integration for persistence
- [ ] Webhook notifications
- [ ] Additional authentication provider integrations

## Support

For issues, questions, or contributions, please open an issue on the repository.

