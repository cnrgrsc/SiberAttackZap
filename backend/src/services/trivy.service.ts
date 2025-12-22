import { PrismaClient } from '@prisma/client';
import { v4 as uuidv4 } from 'uuid';
import axios from 'axios';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { encrypt, decrypt, maskToken } from '../utils/encryption';

const execAsync = promisify(exec);

// Trivy Server URL
const TRIVY_SERVER_URL = process.env.TRIVY_SERVER_URL || 'http://localhost:5004';

// Vulnerability interfaces
interface Vulnerability {
    VulnerabilityID: string;
    PkgName: string;
    InstalledVersion: string;
    FixedVersion?: string;
    Severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
    Title?: string;
    Description?: string;
    References?: string[];
    CVSS?: any;
    PublishedDate?: string;
}

interface SecretFinding {
    RuleID: string;
    Category: string;
    Severity: string;
    Title: string;
    StartLine: number;
    EndLine: number;
    Match: string;
    Layer?: any;
}

interface LicenseFinding {
    Severity: string;
    Category: string;
    PkgName: string;
    FilePath: string;
    Name: string;
    Confidence: number;
    Link?: string;
}

interface ScanResult {
    Target: string;
    Class?: string;
    Type?: string;
    Vulnerabilities?: Vulnerability[];
    Secrets?: SecretFinding[];
    Licenses?: LicenseFinding[];
    Misconfigurations?: any[];
}

interface TrivyScanResponse {
    id?: string;
    scanType: 'image' | 'filesystem' | 'repository' | 'config' | 'sbom';
    target: string;
    scanTime: string;
    results: ScanResult[];
    summary: {
        critical: number;
        high: number;
        medium: number;
        low: number;
        unknown: number;
        total: number;
    };
    secrets?: SecretFinding[];
    licenses?: LicenseFinding[];
    sbom?: any;
}

class TrivyService {
    private prisma = new PrismaClient();

    constructor() {
        console.log('🛡️ Trivy Service initialized');
        console.log(`   Server URL: ${TRIVY_SERVER_URL}`);
    }

    /**
     * Check if Trivy server is healthy
     */
    async healthCheck(): Promise<boolean> {
        try {
            const response = await axios.get(`${TRIVY_SERVER_URL}/healthz`, { timeout: 5000 });
            return response.status === 200;
        } catch (error) {
            console.error('❌ Trivy server health check failed:', error);
            return false;
        }
    }

    /**
     * Scan Docker image for vulnerabilities
     */
    async scanImage(imageName: string, severities: string[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']): Promise<TrivyScanResponse> {
        console.log(`🐳 Scanning Docker image: ${imageName}`);

        try {
            // Use trivy CLI with server mode
            const severityFilter = severities.join(',');
            const command = `trivy image --server ${TRIVY_SERVER_URL} --severity ${severityFilter} --format json ${imageName}`;

            const { stdout, stderr } = await execAsync(command, {
                timeout: 300000, // 5 minutes
                maxBuffer: 50 * 1024 * 1024 // 50MB
            });

            if (stderr && !stderr.includes('INFO') && !stderr.includes('WARN')) {
                console.warn('Trivy stderr:', stderr);
            }

            const result = JSON.parse(stdout);
            return this.formatScanResult(result, 'image', imageName);

        } catch (error: any) {
            console.error('❌ Image scan failed:', error.message);

            // Fallback: Try direct HTTP API if available
            try {
                return await this.scanImageViaAPI(imageName, severities);
            } catch (apiError) {
                throw new Error(`Image scan failed: ${error.message}`);
            }
        }
    }

    /**
     * Scan image via Trivy HTTP API (alternative method)
     */
    private async scanImageViaAPI(imageName: string, severities: string[]): Promise<TrivyScanResponse> {
        // Note: Trivy server mode primarily works with CLI
        // This is a fallback that may not work with all setups
        throw new Error('Direct API scan not available, please ensure Trivy CLI is installed');
    }

    /**
     * Scan filesystem/directory for vulnerabilities
     */
    async scanFilesystem(targetPath: string, severities: string[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']): Promise<TrivyScanResponse> {
        console.log(`📁 Scanning filesystem: ${targetPath}`);

        try {
            const severityFilter = severities.join(',');

            // Convert Windows path to Docker-compatible path for volume mount
            const dockerPath = targetPath.replace(/\\/g, '/');
            const containerMountPath = '/scan-target';

            // Use Docker to run Trivy scan with:
            // - TRIVY_INSECURE=true to skip SSL verification (for corporate networks)
            // - ghcr.io DB repository (more reliable than mirror.gcr.io)
            // - Persistent cache volume for faster subsequent scans
            // - ALL scanners: vuln, secret, misconfig, license (full comprehensive scan)
            const command = `docker run --rm ` +
                `-e TRIVY_INSECURE=true ` +
                `-v trivy-cache:/root/.cache/ ` +
                `-v "${dockerPath}:${containerMountPath}" ` +
                `aquasec/trivy:latest fs ` +
                `--scanners vuln,secret,misconfig,license ` +
                `--db-repository ghcr.io/aquasecurity/trivy-db:2 ` +
                `--java-db-repository ghcr.io/aquasecurity/trivy-java-db:1 ` +
                `--severity ${severityFilter} --format json ${containerMountPath}`;

            console.log(`🐳 Running Docker scan command...`);

            const { stdout, stderr } = await execAsync(command, {
                timeout: 600000, // 10 minutes
                maxBuffer: 50 * 1024 * 1024
            });

            if (stderr && !stderr.includes('INFO') && !stderr.includes('WARN') && !stderr.includes('Downloading')) {
                console.warn('Trivy stderr:', stderr);
            }

            const result = JSON.parse(stdout);
            return this.formatScanResult(result, 'filesystem', targetPath);

        } catch (error: any) {
            console.error('❌ Filesystem scan error:', error.message);
            throw new Error(`Filesystem scan failed: ${error.message}`);
        }
    }


    /**
     * Scan Git repository for vulnerabilities
     */
    async scanRepository(repoUrl: string, severities: string[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']): Promise<TrivyScanResponse> {
        console.log(`📦 Scanning repository: ${repoUrl}`);

        try {
            const severityFilter = severities.join(',');
            const command = `trivy repo --server ${TRIVY_SERVER_URL} --severity ${severityFilter} --format json "${repoUrl}"`;

            const { stdout } = await execAsync(command, {
                timeout: 600000, // 10 minutes for large repos
                maxBuffer: 50 * 1024 * 1024
            });

            const result = JSON.parse(stdout);
            return this.formatScanResult(result, 'repository', repoUrl);

        } catch (error: any) {
            throw new Error(`Repository scan failed: ${error.message}`);
        }
    }

    /**
     * Scan for secrets (passwords, API keys, tokens)
     */
    async scanSecrets(targetPath: string): Promise<TrivyScanResponse> {
        console.log(`🔐 Scanning for secrets: ${targetPath}`);

        try {
            const command = `trivy fs --scanners secret --format json "${targetPath}"`;

            const { stdout } = await execAsync(command, {
                timeout: 300000,
                maxBuffer: 50 * 1024 * 1024
            });

            const result = JSON.parse(stdout);
            return this.formatSecretResult(result, targetPath);

        } catch (error: any) {
            throw new Error(`Secret scan failed: ${error.message}`);
        }
    }

    /**
     * Scan for misconfigurations (Dockerfile, K8s, Terraform, etc.)
     */
    async scanConfig(targetPath: string): Promise<TrivyScanResponse> {
        console.log(`⚙️ Scanning configurations: ${targetPath}`);

        try {
            const command = `trivy config --format json "${targetPath}"`;

            const { stdout } = await execAsync(command, {
                timeout: 300000,
                maxBuffer: 50 * 1024 * 1024
            });

            const result = JSON.parse(stdout);
            return this.formatConfigResult(result, targetPath);

        } catch (error: any) {
            throw new Error(`Config scan failed: ${error.message}`);
        }
    }

    /**
     * Scan for licenses
     */
    async scanLicenses(targetPath: string): Promise<TrivyScanResponse> {
        console.log(`📜 Scanning licenses: ${targetPath}`);

        try {
            const command = `trivy fs --scanners license --format json "${targetPath}"`;

            const { stdout } = await execAsync(command, {
                timeout: 300000,
                maxBuffer: 50 * 1024 * 1024
            });

            const result = JSON.parse(stdout);
            return this.formatLicenseResult(result, targetPath);

        } catch (error: any) {
            throw new Error(`License scan failed: ${error.message}`);
        }
    }

    /**
     * Generate SBOM (Software Bill of Materials)
     */
    async generateSBOM(target: string, format: 'cyclonedx' | 'spdx' = 'cyclonedx'): Promise<any> {
        console.log(`📦 Generating SBOM for: ${target} (format: ${format})`);

        try {
            const formatFlag = format === 'cyclonedx' ? 'cyclonedx' : 'spdx-json';
            const command = `trivy image --format ${formatFlag} ${target}`;

            const { stdout } = await execAsync(command, {
                timeout: 300000,
                maxBuffer: 50 * 1024 * 1024
            });

            return {
                target,
                format,
                generatedAt: new Date().toISOString(),
                sbom: JSON.parse(stdout)
            };

        } catch (error: any) {
            throw new Error(`SBOM generation failed: ${error.message}`);
        }
    }

    /**
     * Format scan result with summary (counts all finding types)
     */
    private formatScanResult(rawResult: any, scanType: TrivyScanResponse['scanType'], target: string): TrivyScanResponse {
        const results: ScanResult[] = Array.isArray(rawResult.Results) ? rawResult.Results : [];

        // Calculate summary for ALL finding types
        let critical = 0, high = 0, medium = 0, low = 0, unknown = 0;
        const allSecrets: SecretFinding[] = [];
        const allLicenses: LicenseFinding[] = [];

        results.forEach(result => {
            // Count Vulnerabilities
            if (result.Vulnerabilities) {
                result.Vulnerabilities.forEach((vuln: Vulnerability) => {
                    switch (vuln.Severity) {
                        case 'CRITICAL': critical++; break;
                        case 'HIGH': high++; break;
                        case 'MEDIUM': medium++; break;
                        case 'LOW': low++; break;
                        default: unknown++; break;
                    }
                });
            }

            // Count Secrets
            if (result.Secrets) {
                result.Secrets.forEach((secret: any) => {
                    allSecrets.push(secret);
                    switch (secret.Severity) {
                        case 'CRITICAL': critical++; break;
                        case 'HIGH': high++; break;
                        case 'MEDIUM': medium++; break;
                        case 'LOW': low++; break;
                        default: unknown++; break;
                    }
                });
            }

            // Count Misconfigurations
            if (result.Misconfigurations) {
                result.Misconfigurations.forEach((mc: any) => {
                    switch (mc.Severity) {
                        case 'CRITICAL': critical++; break;
                        case 'HIGH': high++; break;
                        case 'MEDIUM': medium++; break;
                        case 'LOW': low++; break;
                        default: unknown++; break;
                    }
                });
            }

            // Collect Licenses
            if (result.Licenses) {
                result.Licenses.forEach((lic: any) => {
                    allLicenses.push(lic);
                });
            }
        });

        console.log(`📊 Scan summary: Critical=${critical}, High=${high}, Medium=${medium}, Low=${low}, Secrets=${allSecrets.length}`);

        return {
            scanType,
            target,
            scanTime: new Date().toISOString(),
            results,
            summary: {
                critical,
                high,
                medium,
                low,
                unknown,
                total: critical + high + medium + low + unknown
            },
            secrets: allSecrets.length > 0 ? allSecrets : undefined,
            licenses: allLicenses.length > 0 ? allLicenses : undefined,
        };
    }

    /**
     * Format secret scan result
     */
    private formatSecretResult(rawResult: any, target: string): TrivyScanResponse {
        const results: ScanResult[] = Array.isArray(rawResult.Results) ? rawResult.Results : [];
        const secrets: SecretFinding[] = [];

        results.forEach(result => {
            if (result.Secrets) {
                secrets.push(...result.Secrets);
            }
        });

        return {
            scanType: 'filesystem',
            target,
            scanTime: new Date().toISOString(),
            results,
            summary: {
                critical: secrets.filter(s => s.Severity === 'CRITICAL').length,
                high: secrets.filter(s => s.Severity === 'HIGH').length,
                medium: secrets.filter(s => s.Severity === 'MEDIUM').length,
                low: secrets.filter(s => s.Severity === 'LOW').length,
                unknown: 0,
                total: secrets.length
            },
            secrets
        };
    }

    /**
     * Format config scan result
     */
    private formatConfigResult(rawResult: any, target: string): TrivyScanResponse {
        const results: ScanResult[] = Array.isArray(rawResult.Results) ? rawResult.Results : [];
        let critical = 0, high = 0, medium = 0, low = 0;

        results.forEach(result => {
            if (result.Misconfigurations) {
                result.Misconfigurations.forEach((mc: any) => {
                    switch (mc.Severity) {
                        case 'CRITICAL': critical++; break;
                        case 'HIGH': high++; break;
                        case 'MEDIUM': medium++; break;
                        case 'LOW': low++; break;
                    }
                });
            }
        });

        return {
            scanType: 'config',
            target,
            scanTime: new Date().toISOString(),
            results,
            summary: { critical, high, medium, low, unknown: 0, total: critical + high + medium + low }
        };
    }

    /**
     * Format license scan result
     */
    private formatLicenseResult(rawResult: any, target: string): TrivyScanResponse {
        const results: ScanResult[] = Array.isArray(rawResult.Results) ? rawResult.Results : [];
        const licenses: LicenseFinding[] = [];

        results.forEach(result => {
            if (result.Licenses) {
                licenses.push(...result.Licenses);
            }
        });

        return {
            scanType: 'filesystem',
            target,
            scanTime: new Date().toISOString(),
            results,
            summary: {
                critical: licenses.filter(l => l.Severity === 'CRITICAL').length,
                high: licenses.filter(l => l.Severity === 'HIGH').length,
                medium: licenses.filter(l => l.Severity === 'MEDIUM').length,
                low: licenses.filter(l => l.Severity === 'LOW').length,
                unknown: 0,
                total: licenses.length
            },
            licenses
        };
    }

    /**
     * Save scan result to database
     */
    async saveScanToDatabase(result: TrivyScanResponse, userId?: string): Promise<string> {
        const scanId = uuidv4();

        try {
            await this.prisma.scan.create({
                data: {
                    id: scanId,
                    name: `Trivy ${result.scanType} - ${result.target.split('/').pop() || result.target}`,
                    targetUrl: result.target,
                    scanType: 'TRIVY',
                    status: 'COMPLETED',
                    startedAt: new Date(result.scanTime),
                    completedAt: new Date(),
                    createdBy: userId,
                    metadata: JSON.parse(JSON.stringify({
                        trivyScanType: result.scanType,
                        summary: result.summary,
                        results: result.results?.slice(0, 50), // Limit stored results
                        secrets: result.secrets?.slice(0, 50),
                        licenses: result.licenses?.slice(0, 100),
                    })),
                    environment: 'TRIVY',
                },
            });

            console.log(`✅ Trivy scan saved: ${scanId}`);
            return scanId;

        } catch (error) {
            console.error('❌ Failed to save Trivy scan:', error);
            throw error;
        }
    }

    /**
     * Get Trivy scan history
     */
    async getTrivyScans(limit: number = 50): Promise<any[]> {
        try {
            const scans = await this.prisma.scan.findMany({
                where: { scanType: 'TRIVY' },
                orderBy: { startedAt: 'desc' },
                take: limit,
                select: {
                    id: true,
                    name: true,
                    targetUrl: true,
                    status: true,
                    startedAt: true,
                    completedAt: true,
                    metadata: true,
                },
            });

            return scans.map(scan => ({
                ...scan,
                trivyScanType: (scan.metadata as any)?.trivyScanType,
                summary: (scan.metadata as any)?.summary,
            }));

        } catch (error) {
            console.error('❌ Failed to get Trivy scans:', error);
            return [];
        }
    }

    /**
     * Get scan by ID
     */
    async getScanById(scanId: string): Promise<any | null> {
        try {
            const scan = await this.prisma.scan.findUnique({ where: { id: scanId } });
            if (!scan || scan.scanType !== 'TRIVY') return null;
            return { ...scan, ...(scan.metadata as any) };
        } catch (error) {
            return null;
        }
    }

    /**
     * Generate HTML report with all findings (Vulnerabilities, Misconfigurations, Secrets)
     */
    generateHtmlReport(result: TrivyScanResponse): string {
        const getSeverityColor = (severity: string): string => {
            switch (severity?.toUpperCase()) {
                case 'CRITICAL': return '#ff0000';
                case 'HIGH': return '#ff6600';
                case 'MEDIUM': return '#ffaa00';
                case 'LOW': return '#00aa00';
                default: return '#888888';
            }
        };

        // Collect all findings
        const allVulnerabilities = result.results?.flatMap(r => r.Vulnerabilities || []) || [];
        const allMisconfigurations = result.results?.flatMap(r => r.Misconfigurations || []) || [];
        const allSecrets = result.secrets || result.results?.flatMap(r => r.Secrets || []) || [];

        // Generate vulnerability rows
        const vulnerabilityRows = allVulnerabilities.map(v => `
            <tr>
                <td style="color: ${getSeverityColor(v.Severity)}; font-weight: bold;">${v.Severity}</td>
                <td><code>${v.VulnerabilityID}</code></td>
                <td>${v.PkgName}</td>
                <td>${v.InstalledVersion}</td>
                <td style="color: ${v.FixedVersion ? '#00aa00' : '#888'};">${v.FixedVersion || '-'}</td>
                <td>${v.Title || '-'}</td>
            </tr>
        `).join('');

        // Generate misconfiguration rows
        const misconfigRows = allMisconfigurations.map((mc: any) => `
            <tr>
                <td style="color: ${getSeverityColor(mc.Severity)}; font-weight: bold;">${mc.Severity}</td>
                <td><code>${mc.ID || mc.AVDID || '-'}</code></td>
                <td>${mc.Title || '-'}</td>
                <td>${mc.Type || '-'}</td>
                <td>${mc.Message || mc.Description || '-'}</td>
            </tr>
        `).join('');

        // Generate secret rows
        const secretRows = allSecrets.map((s: any) => `
            <tr>
                <td style="color: ${getSeverityColor(s.Severity)}; font-weight: bold;">${s.Severity}</td>
                <td><code>${s.RuleID || '-'}</code></td>
                <td>${s.Category || '-'}</td>
                <td>${s.Title || '-'}</td>
                <td>${s.StartLine || '-'}</td>
            </tr>
        `).join('');

        return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Trivy Scan Report - ${result.target || 'Security Scan'}</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #1a1a1a; color: #e0e0e0; padding: 20px; margin: 0; }
        .container { max-width: 1400px; margin: 0 auto; background: #2d2d2d; border-radius: 12px; padding: 30px; }
        .header { text-align: center; margin-bottom: 30px; border-bottom: 2px solid #444; padding-bottom: 20px; }
        .header h1 { color: #4fc3f7; margin: 0 0 10px 0; }
        .summary { display: flex; justify-content: center; gap: 20px; margin: 20px 0; flex-wrap: wrap; }
        .summary-item { text-align: center; padding: 15px 25px; border-radius: 8px; min-width: 100px; }
        .summary-item.critical { background: #ff000033; border: 1px solid #ff0000; }
        .summary-item.high { background: #ff660033; border: 1px solid #ff6600; }
        .summary-item.medium { background: #ffaa0033; border: 1px solid #ffaa00; }
        .summary-item.low { background: #00aa0033; border: 1px solid #00aa00; }
        .summary-item .count { font-size: 32px; font-weight: bold; }
        .summary-item .label { font-size: 12px; color: #888; }
        .section { margin: 30px 0; }
        .section h2 { color: #4fc3f7; border-bottom: 1px solid #444; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background: #1a1a1a; padding: 12px; text-align: left; border-bottom: 2px solid #444; }
        td { padding: 10px 12px; border-bottom: 1px solid #333; word-break: break-word; }
        tr:hover { background: #3d3d3d; }
        code { background: #1a1a1a; padding: 2px 6px; border-radius: 4px; font-family: 'Consolas', monospace; }
        .no-findings { text-align: center; padding: 20px; color: #00aa00; font-size: 16px; }
        .footer { text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #444; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Trivy Security Scan Report</h1>
            <p>${result.target || 'Unknown Target'}</p>
            <p style="color: #888; font-size: 12px;">Scan Type: ${result.scanType || 'TRIVY'} | ${result.scanTime ? new Date(result.scanTime).toLocaleString('tr-TR') : new Date().toLocaleString('tr-TR')}</p>
        </div>

        <div class="summary">
            <div class="summary-item critical">
                <div class="count">${result.summary?.critical || 0}</div>
                <div class="label">CRITICAL</div>
            </div>
            <div class="summary-item high">
                <div class="count">${result.summary?.high || 0}</div>
                <div class="label">HIGH</div>
            </div>
            <div class="summary-item medium">
                <div class="count">${result.summary?.medium || 0}</div>
                <div class="label">MEDIUM</div>
            </div>
            <div class="summary-item low">
                <div class="count">${result.summary?.low || 0}</div>
                <div class="label">LOW</div>
            </div>
        </div>

        <!-- Vulnerabilities Section -->
        <div class="section">
            <h2>🐛 Vulnerabilities (${allVulnerabilities.length})</h2>
            ${allVulnerabilities.length > 0 ? `
            <table>
                <thead>
                    <tr>
                        <th style="width: 100px;">Severity</th>
                        <th style="width: 150px;">CVE ID</th>
                        <th>Package</th>
                        <th>Installed</th>
                        <th>Fixed</th>
                        <th>Title</th>
                    </tr>
                </thead>
                <tbody>
                    ${vulnerabilityRows}
                </tbody>
            </table>
            ` : '<p class="no-findings">✅ No vulnerabilities found</p>'}
        </div>

        <!-- Misconfigurations Section -->
        <div class="section">
            <h2>⚙️ Misconfigurations (${allMisconfigurations.length})</h2>
            ${allMisconfigurations.length > 0 ? `
            <table>
                <thead>
                    <tr>
                        <th style="width: 100px;">Severity</th>
                        <th style="width: 100px;">ID</th>
                        <th>Title</th>
                        <th style="width: 150px;">Type</th>
                        <th>Message</th>
                    </tr>
                </thead>
                <tbody>
                    ${misconfigRows}
                </tbody>
            </table>
            ` : '<p class="no-findings">✅ No misconfigurations found</p>'}
        </div>

        <!-- Secrets Section -->
        <div class="section">
            <h2>🔐 Secrets (${allSecrets.length})</h2>
            ${allSecrets.length > 0 ? `
            <table>
                <thead>
                    <tr>
                        <th style="width: 100px;">Severity</th>
                        <th style="width: 150px;">Rule ID</th>
                        <th>Category</th>
                        <th>Title</th>
                        <th style="width: 80px;">Line</th>
                    </tr>
                </thead>
                <tbody>
                    ${secretRows}
                </tbody>
            </table>
            ` : '<p class="no-findings">✅ No secrets found</p>'}
        </div>

        <div class="footer">
            <p>Generated by İBB Güvenlik Tarama Platformu</p>
            <p>Trivy Security Scanner | ${new Date().toLocaleDateString('tr-TR')}</p>
        </div>
    </div>
</body>
</html>
        `;
    }

    /**
     * ======================
     * GIT REPOSITORY METHODS
     * ======================
     */

    /**
     * Save a git repository with encrypted credentials
     */
    async saveRepository(
        userId: string,
        name: string,
        repoUrl: string,
        username: string,
        password: string,
        branch?: string
    ): Promise<any> {
        console.log(`💾 Saving repository: ${name} for user ${userId}`);

        try {
            // Encrypt the password/token
            const encryptedToken = encrypt(password);

            const repository = await this.prisma.gitRepository.create({
                data: {
                    userId,
                    name,
                    repoUrl,
                    username,
                    encryptedToken,
                    branch: branch || 'main',
                },
            });

            // Return without sensitive data
            return {
                id: repository.id,
                name: repository.name,
                repoUrl: repository.repoUrl,
                username: repository.username,
                branch: repository.branch,
                scanCount: repository.scanCount,
                lastUsed: repository.lastUsed,
                createdAt: repository.createdAt,
            };
        } catch (error: any) {
            console.error('❌ Failed to save repository:', error);
            throw new Error(`Failed to save repository: ${error.message}`);
        }
    }

    /**
     * Get user's saved repositories
     */
    async getUserRepositories(userId: string): Promise<any[]> {
        try {
            const repositories = await this.prisma.gitRepository.findMany({
                where: { userId },
                orderBy: { lastUsed: 'desc' },
            });

            // Mask tokens for security
            return repositories.map(repo => ({
                id: repo.id,
                name: repo.name,
                repoUrl: repo.repoUrl,
                username: repo.username,
                maskedToken: maskToken(repo.encryptedToken, 0), // Fully masked
                branch: repo.branch,
                scanCount: repo.scanCount,
                lastUsed: repo.lastUsed,
                createdAt: repo.createdAt,
                updatedAt: repo.updatedAt,
            }));
        } catch (error) {
            console.error('❌ Failed to get repositories:', error);
            return [];
        }
    }

    /**
     * Delete a repository
     */
    async deleteRepository(repoId: string, userId: string): Promise<boolean> {
        try {
            // Check ownership
            const repo = await this.prisma.gitRepository.findUnique({
                where: { id: repoId },
            });

            if (!repo || repo.userId !== userId) {
                throw new Error('Repository not found or unauthorized');
            }

            await this.prisma.gitRepository.delete({
                where: { id: repoId },
            });

            console.log(`🗑️  Deleted repository: ${repo.name}`);
            return true;
        } catch (error: any) {
            console.error('❌ Failed to delete repository:', error);
            throw new Error(`Failed to delete repository: ${error.message}`);
        }
    }

    /**
     * Update repository
     */
    async updateRepository(
        repoId: string,
        userId: string,
        updates: { name?: string; username?: string; password?: string; branch?: string }
    ): Promise<any> {
        try {
            // Check ownership
            const repo = await this.prisma.gitRepository.findUnique({
                where: { id: repoId },
            });

            if (!repo || repo.userId !== userId) {
                throw new Error('Repository not found or unauthorized');
            }

            const data: any = {};
            if (updates.name) data.name = updates.name;
            if (updates.username) data.username = updates.username;
            if (updates.password) data.encryptedToken = encrypt(updates.password);
            if (updates.branch) data.branch = updates.branch;

            const updated = await this.prisma.gitRepository.update({
                where: { id: repoId },
                data,
            });

            return {
                id: updated.id,
                name: updated.name,
                repoUrl: updated.repoUrl,
                username: updated.username,
                branch: updated.branch,
                scanCount: updated.scanCount,
                lastUsed: updated.lastUsed,
            };
        } catch (error: any) {
            console.error('❌ Failed to update repository:', error);
            throw new Error(`Failed to update repository: ${error.message}`);
        }
    }

    /**
     * Clone a git repository with credentials
     */
    private async cloneGitRepository(
        repoUrl: string,
        username: string,
        password: string,
        branch: string,
        targetDir: string
    ): Promise<void> {
        console.log(`📥 Cloning repository: ${repoUrl} to ${targetDir}`);

        // Sanitize credentials for URL
        const encodedUsername = encodeURIComponent(username);
        const encodedPassword = encodeURIComponent(password);

        // Build authenticated URL
        const urlParts = repoUrl.replace('https://', '').replace('http://', '');
        const authenticatedUrl = `https://${encodedUsername}:${encodedPassword}@${urlParts}`;

        try {
            // Clone with timeout and branch
            const command = `git clone --depth 1 --single-branch --branch ${branch} "${authenticatedUrl}" "${targetDir}"`;

            await execAsync(command, {
                timeout: 300000, // 5 minutes
                maxBuffer: 50 * 1024 * 1024, // 50MB
            });

            console.log(`✅ Repository cloned successfully`);
        } catch (error: any) {
            // Mask credentials in error messages
            const safeError = error.message.replace(new RegExp(password, 'g'), '●●●●●●');
            console.error('❌ Git clone failed:', safeError);
            throw new Error(`Failed to clone repository: ${safeError}`);
        }
    }

    /**
     * Scan a saved repository by ID
     */
    async scanSavedRepository(
        repoId: string,
        userId: string,
        severities: string[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    ): Promise<TrivyScanResponse> {
        console.log(`🔍 Scanning saved repository: ${repoId}`);

        try {
            // Get repository from database
            const repo = await this.prisma.gitRepository.findUnique({
                where: { id: repoId },
            });

            if (!repo || repo.userId !== userId) {
                throw new Error('Repository not found or unauthorized');
            }

            // Decrypt credentials
            const password = decrypt(repo.encryptedToken);

            // Perform scan
            const result = await this.scanPrivateRepositoryInternal(
                repo.repoUrl,
                repo.username,
                password,
                repo.branch || 'main',
                severities
            );

            // Update last used time and scan count
            await this.prisma.gitRepository.update({
                where: { id: repoId },
                data: {
                    lastUsed: new Date(),
                    scanCount: { increment: 1 },
                },
            });

            return result;
        } catch (error: any) {
            console.error('❌ Saved repository scan failed:', error);
            throw new Error(`Failed to scan saved repository: ${error.message}`);
        }
    }

    /**
     * Scan a private repository (one-time, without saving)
     */
    async scanPrivateRepository(
        repoUrl: string,
        username: string,
        password: string,
        branch: string = 'main',
        severities: string[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    ): Promise<TrivyScanResponse> {
        return this.scanPrivateRepositoryInternal(repoUrl, username, password, branch, severities);
    }

    /**
     * Internal method to scan a private repository
     */
    private async scanPrivateRepositoryInternal(
        repoUrl: string,
        username: string,
        password: string,
        branch: string,
        severities: string[]
    ): Promise<TrivyScanResponse> {
        console.log(`🔐 Scanning private repository: ${repoUrl} (branch: ${branch})`);

        // Use os.tmpdir() for cross-platform compatibility (Windows, Linux, Mac)
        const tempDir = path.join(os.tmpdir(), `trivy-scan-${uuidv4()}`);

        try {
            // Ensure temp directory exists
            if (!fs.existsSync(os.tmpdir())) {
                fs.mkdirSync(os.tmpdir(), { recursive: true });
            }

            // Clone the repository
            await this.cloneGitRepository(repoUrl, username, password, branch, tempDir);

            // Scan the cloned repository using filesystem scan
            console.log(`🔎 Scanning cloned repository...`);
            const result = await this.scanFilesystem(tempDir, severities);

            result.target = `${repoUrl} (${branch})`;
            result.scanType = 'repository';

            return result;
        } catch (error: any) {
            console.error('❌ Private repository scan failed:', error);
            throw error;
        } finally {
            // Cleanup: Remove cloned repository
            try {
                if (fs.existsSync(tempDir)) {
                    console.log(`🧹 Cleaning up: ${tempDir}`);
                    fs.rmSync(tempDir, { recursive: true, force: true });
                }
            } catch (cleanupError) {
                console.error('⚠️  Cleanup failed:', cleanupError);
            }
        }
    }
}

// Export singleton
export const trivyService = new TrivyService();
export { TrivyScanResponse, Vulnerability, SecretFinding, LicenseFinding, ScanResult };
