import sqlite3 from 'sqlite3';
import { LoginAttempt, UserProfile, RiskAssessment } from '../types';

interface DatabaseRow {
  [key: string]: any;
}

export class Database {
  private db: sqlite3.Database;

  constructor(dbPath: string = './suspicious_logins.db') {
    this.db = new sqlite3.Database(dbPath);
    this.initializeTables();
  }

  private async initializeTables(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.db.serialize(() => {
        // Create user_profiles table
        this.db.run(`
          CREATE TABLE IF NOT EXISTS user_profiles (
            user_id TEXT PRIMARY KEY,
            typical_locations TEXT,
            typical_login_hours TEXT,
            last_successful_login TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
          )
        `);

        // Create login_attempts table
        this.db.run(`
          CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            timestamp DATETIME NOT NULL,
            ip_address TEXT NOT NULL,
            success BOOLEAN NOT NULL,
            user_agent TEXT,
            session_id TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES user_profiles (user_id)
          )
        `);

        // Create risk_assessments table
        this.db.run(`
          CREATE TABLE IF NOT EXISTS risk_assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            timestamp DATETIME NOT NULL,
            overall_risk INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            location_change_risk INTEGER NOT NULL,
            impossible_travel_risk INTEGER NOT NULL,
            brute_force_risk INTEGER NOT NULL,
            unusual_time_risk INTEGER NOT NULL,
            recommendations TEXT,
            details TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES user_profiles (user_id)
          )
        `);

        // Create indexes for better performance
        this.db.run(`CREATE INDEX IF NOT EXISTS idx_login_attempts_user_id ON login_attempts(user_id)`);
        this.db.run(`CREATE INDEX IF NOT EXISTS idx_login_attempts_timestamp ON login_attempts(timestamp)`);
        this.db.run(`CREATE INDEX IF NOT EXISTS idx_risk_assessments_user_id ON risk_assessments(user_id)`);
        this.db.run(`CREATE INDEX IF NOT EXISTS idx_risk_assessments_timestamp ON risk_assessments(timestamp)`, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
    });
  }

  // User Profile Methods
  async saveUserProfile(profile: UserProfile): Promise<void> {
    return new Promise((resolve, reject) => {
      this.db.run(`
        INSERT OR REPLACE INTO user_profiles 
        (user_id, typical_locations, typical_login_hours, last_successful_login, updated_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
      `, [
        profile.userId,
        JSON.stringify(profile.typicalLocations),
        JSON.stringify(profile.typicalLoginHours),
        profile.lastSuccessfulLogin ? JSON.stringify(profile.lastSuccessfulLogin) : null
      ], (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  async getUserProfile(userId: string): Promise<UserProfile | null> {
    return new Promise((resolve, reject) => {
      this.db.get(`
        SELECT * FROM user_profiles WHERE user_id = ?
      `, [userId], async (err, row: DatabaseRow) => {
        if (err) {
          reject(err);
          return;
        }
        
        if (!row) {
          resolve(null);
          return;
        }

        try {
          const profile: UserProfile = {
            userId: row.user_id,
            loginHistory: await this.getUserLoginHistory(userId),
            typicalLocations: JSON.parse(row.typical_locations || '[]'),
            typicalLoginHours: JSON.parse(row.typical_login_hours || '[]'),
            lastSuccessfulLogin: row.last_successful_login ? JSON.parse(row.last_successful_login) : undefined,
            failedAttempts: await this.getUserFailedAttempts(userId)
          };
          resolve(profile);
        } catch (error) {
          reject(error);
        }
      });
    });
  }

  // Login Attempt Methods
  async saveLoginAttempt(attempt: LoginAttempt): Promise<void> {
    return new Promise((resolve, reject) => {
      this.db.run(`
        INSERT INTO login_attempts 
        (user_id, timestamp, ip_address, success, user_agent, session_id)
        VALUES (?, ?, ?, ?, ?, ?)
      `, [
        attempt.userId,
        attempt.timestamp.toISOString(),
        attempt.ipAddress,
        attempt.success ? 1 : 0,
        attempt.userAgent || null,
        attempt.sessionId || null
      ], (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  async getUserLoginHistory(userId: string): Promise<LoginAttempt[]> {
    return new Promise((resolve, reject) => {
      this.db.all(`
        SELECT * FROM login_attempts 
        WHERE user_id = ? 
        ORDER BY timestamp DESC
      `, [userId], (err, rows: DatabaseRow[]) => {
        if (err) {
          reject(err);
          return;
        }

        const attempts = rows.map(row => ({
          userId: row.user_id,
          timestamp: new Date(row.timestamp),
          ipAddress: row.ip_address,
          success: Boolean(row.success),
          userAgent: row.user_agent,
          sessionId: row.session_id
        }));
        resolve(attempts);
      });
    });
  }

  async getUserFailedAttempts(userId: string): Promise<LoginAttempt[]> {
    return new Promise((resolve, reject) => {
      this.db.all(`
        SELECT * FROM login_attempts 
        WHERE user_id = ? AND success = 0
        ORDER BY timestamp DESC
      `, [userId], (err, rows: DatabaseRow[]) => {
        if (err) {
          reject(err);
          return;
        }

        const attempts = rows.map(row => ({
          userId: row.user_id,
          timestamp: new Date(row.timestamp),
          ipAddress: row.ip_address,
          success: false,
          userAgent: row.user_agent,
          sessionId: row.session_id
        }));
        resolve(attempts);
      });
    });
  }

  // Risk Assessment Methods
  async saveRiskAssessment(assessment: RiskAssessment): Promise<void> {
    return new Promise((resolve, reject) => {
      this.db.run(`
        INSERT INTO risk_assessments 
        (user_id, timestamp, overall_risk, risk_level, location_change_risk, 
         impossible_travel_risk, brute_force_risk, unusual_time_risk, 
         recommendations, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [
        assessment.userId,
        assessment.timestamp.toISOString(),
        assessment.overallRisk,
        assessment.riskLevel,
        assessment.factors.locationChange,
        assessment.factors.impossibleTravel,
        assessment.factors.bruteForce,
        assessment.factors.unusualTime,
        JSON.stringify(assessment.recommendations),
        JSON.stringify(assessment.details)
      ], (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  async getRiskAssessments(userId?: string, limit: number = 100): Promise<RiskAssessment[]> {
    return new Promise((resolve, reject) => {
      let query = `SELECT * FROM risk_assessments `;
      const params: any[] = [];

      if (userId) {
        query += `WHERE user_id = ? `;
        params.push(userId);
      }

      query += `ORDER BY timestamp DESC LIMIT ?`;
      params.push(limit);

      this.db.all(query, params, (err, rows: DatabaseRow[]) => {
        if (err) {
          reject(err);
          return;
        }

        const assessments = rows.map(row => ({
          userId: row.user_id,
          timestamp: new Date(row.timestamp),
          overallRisk: row.overall_risk,
          riskLevel: row.risk_level,
          factors: {
            locationChange: row.location_change_risk,
            impossibleTravel: row.impossible_travel_risk,
            bruteForce: row.brute_force_risk,
            unusualTime: row.unusual_time_risk
          },
          recommendations: JSON.parse(row.recommendations || '[]'),
          details: JSON.parse(row.details || '[]')
        }));
        resolve(assessments);
      });
    });
  }

  // Analytics Methods
  async getDashboardStats(): Promise<any> {
    return new Promise((resolve, reject) => {
      const stats: any = {};
      let completed = 0;
      const total = 5;

      const checkComplete = () => {
        completed++;
        if (completed === total) {
          resolve(stats);
        }
      };

      // Total logins
      this.db.get(`SELECT COUNT(*) as count FROM login_attempts`, (err, row: DatabaseRow) => {
        if (err) reject(err);
        else {
          stats.totalLogins = row.count;
          checkComplete();
        }
      });

      // Suspicious logins
      this.db.get(`SELECT COUNT(*) as count FROM risk_assessments WHERE risk_level IN ('high', 'critical')`, (err, row: DatabaseRow) => {
        if (err) reject(err);
        else {
          stats.suspiciousLogins = row.count;
          checkComplete();
        }
      });

      // Unique users
      this.db.get(`SELECT COUNT(DISTINCT user_id) as count FROM login_attempts`, (err, row: DatabaseRow) => {
        if (err) reject(err);
        else {
          stats.uniqueUsers = row.count;
          checkComplete();
        }
      });

      // Recent high-risk assessments
      this.db.all(`
        SELECT ra.*, la.ip_address 
        FROM risk_assessments ra
        LEFT JOIN login_attempts la ON ra.user_id = la.user_id AND ra.timestamp = la.timestamp
        WHERE ra.risk_level IN ('high', 'critical')
        ORDER BY ra.timestamp DESC
        LIMIT 10
      `, (err, rows: DatabaseRow[]) => {
        if (err) reject(err);
        else {
          stats.recentHighRisk = rows.map(row => ({
            userId: row.user_id,
            timestamp: row.timestamp,
            riskLevel: row.risk_level,
            overallRisk: row.overall_risk,
            ipAddress: row.ip_address
          }));
          checkComplete();
        }
      });

      // Risk level breakdown
      this.db.all(`SELECT risk_level, COUNT(*) as count FROM risk_assessments GROUP BY risk_level`, (err, rows: DatabaseRow[]) => {
        if (err) reject(err);
        else {
          stats.riskBreakdown = rows.reduce((acc: any, row) => {
            acc[row.risk_level] = row.count;
            return acc;
          }, {});
          checkComplete();
        }
      });
    });
  }

  async close(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.db.close((err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }
}

// Singleton instance
let dbInstance: Database | null = null;

export function getDatabase(): Database {
  if (!dbInstance) {
    dbInstance = new Database();
  }
  return dbInstance;
}