import express, { Request, Response } from 'express';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import path from 'path';
import { SuspiciousLoginDetector } from '../core/detector';
import { LoginAttempt, DetectorConfig } from '../types';
import { getDatabase } from '../database/database';

const app = express();
const server = createServer(app);
const io = new SocketIOServer(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});
const port = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, '../../public')));

// Initialize detector and database
const detector = new SuspiciousLoginDetector();
const db = getDatabase();

/**
 * Serve dashboard
 */
app.get('/', (req: Request, res: Response) => {
  res.sendFile(path.join(__dirname, '../../public/index.html'));
});

/**
 * Health check endpoint
 */
app.get('/health', (req: Request, res: Response) => {
  res.json({ status: 'ok', message: 'Suspicious Login Detector API is running' });
});

/**
 * POST /api/login/check
 * Analyze a single login attempt
 */
app.post('/api/login/check', async (req: Request, res: Response) => {
  try {
    const loginAttempt: LoginAttempt = {
      userId: req.body.userId,
      timestamp: new Date(req.body.timestamp || Date.now()),
      ipAddress: req.body.ipAddress,
      success: req.body.success ?? true,
      userAgent: req.body.userAgent,
      sessionId: req.body.sessionId
    };

    // Validate required fields
    if (!loginAttempt.userId || !loginAttempt.ipAddress) {
      return res.status(400).json({
        error: 'Missing required fields: userId and ipAddress are required'
      });
    }

    const assessment = await detector.analyzeLogin(loginAttempt);
    
    // Emit real-time update to connected clients
    io.emit('login_analyzed', {
      ...assessment,
      ipAddress: loginAttempt.ipAddress,
      success: loginAttempt.success
    });
    
    res.json(assessment);
  } catch (error) {
    console.error('Error analyzing login:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /api/login/batch
 * Analyze multiple login attempts
 */
app.post('/api/login/batch', async (req: Request, res: Response) => {
  try {
    const attempts: LoginAttempt[] = req.body.attempts;

    if (!Array.isArray(attempts)) {
      return res.status(400).json({
        error: 'Invalid request: attempts array is required'
      });
    }

    // Validate and convert timestamps
    const validatedAttempts: LoginAttempt[] = attempts.map(attempt => ({
      userId: attempt.userId,
      timestamp: new Date(attempt.timestamp || Date.now()),
      ipAddress: attempt.ipAddress,
      success: attempt.success ?? true,
      userAgent: attempt.userAgent,
      sessionId: attempt.sessionId
    }));

    const assessments = await detector.analyzeMultiple(validatedAttempts);
    res.json({ results: assessments, total: assessments.length });
  } catch (error) {
    console.error('Error analyzing batch:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /api/user/:userId/history
 * Get login history for a user
 */
app.get('/api/user/:userId/history', async (req: Request, res: Response) => {
  try {
    const userId = req.params.userId;
    const profile = await detector.getUserProfileData(userId);

    if (!profile) {
      return res.status(404).json({
        error: 'User not found',
        message: `No login history found for user: ${userId}`
      });
    }

    res.json({
      userId: profile.userId,
      totalLogins: profile.loginHistory.length,
      successfulLogins: profile.loginHistory.filter(l => l.success).length,
      failedLogins: profile.failedAttempts.length,
      history: profile.loginHistory,
      lastSuccessfulLogin: profile.lastSuccessfulLogin
    });
  } catch (error) {
    console.error('Error fetching history:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /api/user/:userId/risk-profile
 * Get risk profile summary for a user
 */
app.get('/api/user/:userId/risk-profile', async (req: Request, res: Response) => {
  try {
    const userId = req.params.userId;
    const profile = await detector.getUserProfileData(userId);

    if (!profile) {
      return res.status(404).json({
        error: 'User not found',
        message: `No profile found for user: ${userId}`
      });
    }

    res.json({
      userId: profile.userId,
      totalLogins: profile.loginHistory.length,
      failedAttempts: profile.failedAttempts.length,
      typicalLocations: profile.typicalLocations,
      typicalLoginHours: profile.typicalLoginHours,
      lastSuccessfulLogin: profile.lastSuccessfulLogin
    });
  } catch (error) {
    console.error('Error fetching risk profile:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /api/stats
 * Get overall statistics
 */
app.get('/api/stats', async (req: Request, res: Response) => {
  try {
    const stats = await detector.getDashboardStats();
    res.json(stats);
  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /api/risk-assessments
 * Get recent risk assessments
 */
app.get('/api/risk-assessments', async (req: Request, res: Response) => {
  try {
    const limit = parseInt(req.query.limit as string) || 50;
    const assessments = await detector.getRecentRiskAssessments(limit);
    res.json({ assessments, total: assessments.length });
  } catch (error) {
    console.error('Error fetching risk assessments:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// WebSocket connection handling
io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);
  
  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
  
  // Send initial dashboard data
  socket.emit('dashboard_data', { message: 'Connected to live updates' });
});

// Start server
if (require.main === module) {
  server.listen(port, () => {
    console.log(`Suspicious Login Detector API listening on port ${port}`);
    console.log(`Dashboard: http://localhost:${port}`);
    console.log(`Health check: http://localhost:${port}/health`);
    console.log('\nAvailable endpoints:');
    console.log(`  GET    http://localhost:${port}/                    # Dashboard`);
    console.log(`  POST   http://localhost:${port}/api/login/check`);
    console.log(`  POST   http://localhost:${port}/api/login/batch`);
    console.log(`  GET    http://localhost:${port}/api/user/:userId/history`);
    console.log(`  GET    http://localhost:${port}/api/user/:userId/risk-profile`);
    console.log(`  GET    http://localhost:${port}/api/stats`);
    console.log(`  GET    http://localhost:${port}/api/risk-assessments`);
  });
}

export default app;

