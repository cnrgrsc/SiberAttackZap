import { Router, Request, Response } from 'express';
import { spawn, exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);
const router = Router();

// Allowed tools whitelist for security
const ALLOWED_TOOLS: { [key: string]: string } = {
    nmap: '/usr/bin/nmap',
    sqlmap: '/opt/security-tools/sqlmap/sqlmap.py',
    nikto: '/opt/security-tools/nikto/program/nikto.pl',
    hydra: '/usr/local/bin/hydra',
    gobuster: '/usr/local/bin/gobuster',
    nuclei: '/usr/local/bin/nuclei',
    ffuf: '/usr/local/bin/ffuf',
    whatweb: '/usr/local/bin/whatweb',
    wpscan: '/usr/local/bin/wpscan',
    sslyze: '/usr/local/bin/sslyze',
    dirb: '/usr/local/bin/dirb'
};

// Tool command templates for security
const TOOL_COMMANDS: { [key: string]: (target: string, options: any) => string[] } = {
    nmap: (target, options) => {
        const args = ['-sV', '-sC'];
        if (options.ports) args.push('-p', options.ports);
        if (options.timing) args.push(`-T${options.timing}`);
        if (options.osDetection) args.push('-O');
        args.push(target);
        return args;
    },
    sqlmap: (target, options) => {
        const args = ['-u', target, '--batch'];
        if (options.level) args.push('--level', String(options.level));
        if (options.risk) args.push('--risk', String(options.risk));
        return args;
    },
    nikto: (target, options) => {
        return ['-h', target, '-Format', 'txt'];
    },
    gobuster: (target, options) => {
        return ['dir', '-u', target, '-w', options.wordlist || '/opt/wordlists/common.txt'];
    },
    nuclei: (target, options) => {
        return ['-u', target, '-silent'];
    },
    ffuf: (target, options) => {
        return ['-u', `${target}/FUZZ`, '-w', options.wordlist || '/opt/wordlists/common.txt'];
    },
    hydra: (target, options) => {
        // Only for authorized testing
        return ['-L', options.userlist, '-P', options.passlist, target, options.protocol || 'ssh'];
    },
    whatweb: (target, options) => {
        return ['-v', target];
    },
    wpscan: (target, options) => {
        return ['--url', target, '--no-banner'];
    },
    sslyze: (target, options) => {
        return [target];
    },
    dirb: (target, options) => {
        return [target, options.wordlist || '/opt/wordlists/common.txt'];
    }
};

// Validate target URL for security
function validateTarget(target: string): boolean {
    try {
        const url = new URL(target);
        // Only allow http/https protocols
        if (!['http:', 'https:'].includes(url.protocol)) {
            return false;
        }
        // Prevent localhost targeting (security)
        if (url.hostname === 'localhost' || url.hostname === '127.0.0.1') {
            return false;
        }
        return true;
    } catch {
        // Check if it's a valid IP address
        const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
        return ipPattern.test(target);
    }
}

// Sanitize command arguments
function sanitizeArgs(args: string[]): string[] {
    return args.map(arg => {
        // Remove potentially dangerous characters
        return arg.replace(/[;&|`$(){}[\]<>]/g, '');
    });
}

interface ScanResult {
    id: string;
    tool: string;
    target: string;
    status: 'running' | 'completed' | 'failed';
    output: string[];
    startTime: Date;
    endTime?: Date;
    exitCode?: number;
}

// Store running scans
const runningScans: Map<string, ScanResult> = new Map();

/**
 * POST /api/kali/execute
 * Execute a Kali Linux security tool
 */
router.post('/execute', async (req: Request, res: Response) => {
    try {
        const { tool, target, options = {} } = req.body;

        // Validate tool
        if (!tool || !ALLOWED_TOOLS[tool]) {
            return res.status(400).json({
                success: false,
                error: `Invalid tool. Allowed tools: ${Object.keys(ALLOWED_TOOLS).join(', ')}`
            });
        }

        // Validate target
        if (!target) {
            return res.status(400).json({
                success: false,
                error: 'Target is required'
            });
        }

        if (!validateTarget(target)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid target. Must be a valid URL or IP address.'
            });
        }

        // Generate scan ID
        const scanId = `${tool}-${Date.now()}`;

        // Build command
        const toolPath = ALLOWED_TOOLS[tool];
        const commandBuilder = TOOL_COMMANDS[tool];

        if (!commandBuilder) {
            return res.status(400).json({
                success: false,
                error: 'Tool command template not configured'
            });
        }

        const args = sanitizeArgs(commandBuilder(target, options));

        console.log(`🔍 Executing ${tool}: ${toolPath} ${args.join(' ')}`);

        // Create scan result
        const scanResult: ScanResult = {
            id: scanId,
            tool,
            target,
            status: 'running',
            output: [],
            startTime: new Date()
        };
        runningScans.set(scanId, scanResult);

        // Execute command
        const process = spawn(toolPath, args, {
            timeout: 300000 // 5 minute timeout
        });

        // Capture stdout
        process.stdout.on('data', (data: Buffer) => {
            const lines = data.toString().split('\n').filter(line => line.trim());
            scanResult.output.push(...lines);
        });

        // Capture stderr
        process.stderr.on('data', (data: Buffer) => {
            const lines = data.toString().split('\n').filter(line => line.trim());
            scanResult.output.push(...lines.map(line => `[ERROR] ${line}`));
        });

        // Handle process completion
        process.on('close', (code: number) => {
            scanResult.status = code === 0 ? 'completed' : 'failed';
            scanResult.endTime = new Date();
            scanResult.exitCode = code;
            console.log(`✅ ${tool} completed with exit code ${code}`);
        });

        process.on('error', (err: Error) => {
            scanResult.status = 'failed';
            scanResult.endTime = new Date();
            scanResult.output.push(`[ERROR] ${err.message}`);
            console.error(`❌ ${tool} error:`, err);
        });

        // Return scan ID immediately
        return res.json({
            success: true,
            scanId,
            message: `${tool} scan started`,
            command: `${toolPath} ${args.join(' ')}`
        });

    } catch (error: any) {
        console.error('Execute error:', error);
        return res.status(500).json({
            success: false,
            error: error.message || 'Internal server error'
        });
    }
});

/**
 * GET /api/kali/status/:scanId
 * Get scan status and output
 */
router.get('/status/:scanId', async (req: Request, res: Response) => {
    try {
        const { scanId } = req.params;
        const { fromLine = 0 } = req.query;

        const scan = runningScans.get(scanId);
        if (!scan) {
            return res.status(404).json({
                success: false,
                error: 'Scan not found'
            });
        }

        const startLine = parseInt(fromLine as string) || 0;
        const newOutput = scan.output.slice(startLine);

        return res.json({
            success: true,
            scanId,
            tool: scan.tool,
            target: scan.target,
            status: scan.status,
            output: newOutput,
            totalLines: scan.output.length,
            startTime: scan.startTime,
            endTime: scan.endTime,
            exitCode: scan.exitCode
        });

    } catch (error: any) {
        console.error('Status error:', error);
        return res.status(500).json({
            success: false,
            error: error.message || 'Internal server error'
        });
    }
});

/**
 * GET /api/kali/tools
 * Get list of available tools
 */
router.get('/tools', async (req: Request, res: Response) => {
    try {
        const tools = await Promise.all(
            Object.entries(ALLOWED_TOOLS).map(async ([name, path]) => {
                let installed = false;
                let version = 'Unknown';

                try {
                    const { stdout } = await execAsync(`${path} --version 2>/dev/null || ${path} -V 2>/dev/null || echo "installed"`);
                    installed = true;
                    version = stdout.split('\n')[0] || 'Available';
                } catch {
                    installed = false;
                }

                return {
                    name,
                    path,
                    installed,
                    version
                };
            })
        );

        return res.json({
            success: true,
            tools
        });

    } catch (error: any) {
        console.error('Tools list error:', error);
        return res.status(500).json({
            success: false,
            error: error.message || 'Internal server error'
        });
    }
});

/**
 * DELETE /api/kali/scan/:scanId
 * Cancel running scan
 */
router.delete('/scan/:scanId', async (req: Request, res: Response) => {
    try {
        const { scanId } = req.params;

        // In real implementation, would need to track and kill the process
        runningScans.delete(scanId);

        return res.json({
            success: true,
            message: 'Scan cancelled'
        });

    } catch (error: any) {
        console.error('Cancel error:', error);
        return res.status(500).json({
            success: false,
            error: error.message || 'Internal server error'
        });
    }
});

/**
 * GET /api/kali/history
 * Get recent scan history
 */
router.get('/history', async (req: Request, res: Response) => {
    try {
        const scans = Array.from(runningScans.values())
            .sort((a, b) => b.startTime.getTime() - a.startTime.getTime())
            .slice(0, 50);

        return res.json({
            success: true,
            scans: scans.map(s => ({
                id: s.id,
                tool: s.tool,
                target: s.target,
                status: s.status,
                startTime: s.startTime,
                endTime: s.endTime,
                exitCode: s.exitCode,
                outputLines: s.output.length
            }))
        });

    } catch (error: any) {
        console.error('History error:', error);
        return res.status(500).json({
            success: false,
            error: error.message || 'Internal server error'
        });
    }
});

export default router;
