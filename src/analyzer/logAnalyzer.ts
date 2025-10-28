import * as fs from 'fs';
import * as path from 'path';
import { SuspiciousLoginDetector } from '../core/detector';
import { LoginAttempt, AnalysisReport, RiskAssessment } from '../types';

/**
 * Log Analyzer for processing historical login data
 */
export class LogAnalyzer {
  private detector: SuspiciousLoginDetector;

  constructor() {
    this.detector = new SuspiciousLoginDetector();
  }

  /**
   * Analyze login logs from a JSON file
   */
  async analyzeFromJSON(filePath: string): Promise<AnalysisReport> {
    try {
      const fileContent = fs.readFileSync(filePath, 'utf-8');
      const data = JSON.parse(fileContent);
      
      // Support both array of logins and object with 'logins' property
      const logins: any[] = Array.isArray(data) ? data : data.logins || [];
      
      return await this.analyzeLogins(logins);
    } catch (error) {
      throw new Error(`Failed to read JSON file: ${error}`);
    }
  }

  /**
   * Analyze login logs from a CSV file
   */
  async analyzeFromCSV(filePath: string): Promise<AnalysisReport> {
    try {
      const fileContent = fs.readFileSync(filePath, 'utf-8');
      const lines = fileContent.split('\n').filter(line => line.trim());
      
      // Assume first line is header
      const headers = lines[0].split(',').map(h => h.trim());
      const logins: any[] = [];
      
      for (let i = 1; i < lines.length; i++) {
        const values = lines[i].split(',').map(v => v.trim());
        const login: any = {};
        
        headers.forEach((header, index) => {
          login[header] = values[index];
        });
        
        logins.push(login);
      }
      
      return await this.analyzeLogins(logins);
    } catch (error) {
      throw new Error(`Failed to read CSV file: ${error}`);
    }
  }

  /**
   * Analyze array of login data
   */
  private async analyzeLogins(logins: any[]): Promise<AnalysisReport> {
    const loginAttempts: LoginAttempt[] = logins.map(login => ({
      userId: login.userId || login.user_id,
      timestamp: new Date(login.timestamp),
      ipAddress: login.ipAddress || login.ip_address || login.ip,
      success: login.success === 'true' || login.success === true || login.success === 1,
      userAgent: login.userAgent || login.user_agent,
      sessionId: login.sessionId || login.session_id
    }));

    // Sort by timestamp to process in chronological order
    loginAttempts.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

    // Analyze all logins
    const assessments = await this.detector.analyzeMultiple(loginAttempts);

    // Generate report
    return this.generateReport(loginAttempts, assessments);
  }

  /**
   * Generate analysis report
   */
  private generateReport(
    logins: LoginAttempt[],
    assessments: RiskAssessment[]
  ): AnalysisReport {
    const suspiciousLogins = assessments.filter(
      a => a.riskLevel === 'high' || a.riskLevel === 'critical'
    );

    const uniqueUsers = new Set(logins.map(l => l.userId));
    
    const highRiskUsers = Array.from(
      new Set(
        suspiciousLogins.map(a => a.userId)
      )
    );

    return {
      totalLogins: logins.length,
      suspiciousLogins: suspiciousLogins.length,
      usersAnalyzed: uniqueUsers.size,
      highRiskUsers,
      reportGeneratedAt: new Date(),
      detailedResults: assessments
    };
  }

  /**
   * Export report to JSON file
   */
  exportToJSON(report: AnalysisReport, outputPath: string): void {
    const jsonContent = JSON.stringify(report, null, 2);
    fs.writeFileSync(outputPath, jsonContent, 'utf-8');
    console.log(`Report exported to: ${outputPath}`);
  }

  /**
   * Export report to CSV file
   */
  exportToCSV(report: AnalysisReport, outputPath: string): void {
    const headers = [
      'userId',
      'timestamp',
      'overallRisk',
      'riskLevel',
      'locationChange',
      'impossibleTravel',
      'bruteForce',
      'unusualTime'
    ];

    const rows = report.detailedResults.map(result => [
      result.userId,
      result.timestamp.toISOString(),
      result.overallRisk,
      result.riskLevel,
      result.factors.locationChange,
      result.factors.impossibleTravel,
      result.factors.bruteForce,
      result.factors.unusualTime
    ]);

    const csvContent = [
      headers.join(','),
      ...rows.map(row => row.join(','))
    ].join('\n');

    fs.writeFileSync(outputPath, csvContent, 'utf-8');
    console.log(`Report exported to: ${outputPath}`);
  }

  /**
   * Print report summary to console
   */
  printSummary(report: AnalysisReport): void {
    console.log('\n' + '='.repeat(60));
    console.log('SUSPICIOUS LOGIN DETECTION REPORT');
    console.log('='.repeat(60));
    console.log(`Generated: ${report.reportGeneratedAt.toISOString()}`);
    console.log(`Total Logins Analyzed: ${report.totalLogins}`);
    console.log(`Users Analyzed: ${report.usersAnalyzed}`);
    console.log(`Suspicious Logins: ${report.suspiciousLogins} (${((report.suspiciousLogins / report.totalLogins) * 100).toFixed(2)}%)`);
    console.log(`High Risk Users: ${report.highRiskUsers.length}`);
    
    if (report.highRiskUsers.length > 0) {
      console.log('\nHigh Risk User IDs:');
      report.highRiskUsers.forEach(userId => {
        console.log(`  - ${userId}`);
      });
    }

    // Risk level breakdown
    const riskBreakdown = {
      low: 0,
      medium: 0,
      high: 0,
      critical: 0
    };

    report.detailedResults.forEach(result => {
      riskBreakdown[result.riskLevel]++;
    });

    console.log('\nRisk Level Breakdown:');
    console.log(`  Low:      ${riskBreakdown.low} (${((riskBreakdown.low / report.totalLogins) * 100).toFixed(1)}%)`);
    console.log(`  Medium:   ${riskBreakdown.medium} (${((riskBreakdown.medium / report.totalLogins) * 100).toFixed(1)}%)`);
    console.log(`  High:     ${riskBreakdown.high} (${((riskBreakdown.high / report.totalLogins) * 100).toFixed(1)}%)`);
    console.log(`  Critical: ${riskBreakdown.critical} (${((riskBreakdown.critical / report.totalLogins) * 100).toFixed(1)}%)`);
    
    console.log('='.repeat(60) + '\n');
  }
}

/**
 * CLI interface for log analyzer
 */
async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.log('Usage: npm run analyze <input-file> [output-file]');
    console.log('\nSupported formats: .json, .csv');
    console.log('\nExample:');
    console.log('  npm run analyze sample-data/logins.json');
    console.log('  npm run analyze sample-data/logins.json output/report.json');
    console.log('  npm run analyze sample-data/logins.csv output/report.csv');
    process.exit(1);
  }

  const inputFile = args[0];
  const outputFile = args[1];

  if (!fs.existsSync(inputFile)) {
    console.error(`Error: File not found: ${inputFile}`);
    process.exit(1);
  }

  const analyzer = new LogAnalyzer();
  const ext = path.extname(inputFile).toLowerCase();

  console.log(`Analyzing login logs from: ${inputFile}`);
  console.log('Please wait...\n');

  try {
    let report;

    if (ext === '.json') {
      report = await analyzer.analyzeFromJSON(inputFile);
    } else if (ext === '.csv') {
      report = await analyzer.analyzeFromCSV(inputFile);
    } else {
      console.error('Error: Unsupported file format. Use .json or .csv');
      process.exit(1);
    }

    analyzer.printSummary(report);

    if (outputFile) {
      const outputExt = path.extname(outputFile).toLowerCase();
      
      if (outputExt === '.json') {
        analyzer.exportToJSON(report, outputFile);
      } else if (outputExt === '.csv') {
        analyzer.exportToCSV(report, outputFile);
      } else {
        console.error('Error: Output format must be .json or .csv');
        process.exit(1);
      }
    }

  } catch (error) {
    console.error('Error analyzing logs:', error);
    process.exit(1);
  }
}

// Run CLI if this file is executed directly
if (require.main === module) {
  main();
}

export default LogAnalyzer;

