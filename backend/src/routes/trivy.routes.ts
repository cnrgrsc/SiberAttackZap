import { Router, Request, Response } from 'express';
import { trivyService } from '../services/trivy.service';
import multer from 'multer';
import path from 'path';
import fs from 'fs';

const router = Router();

// Configure multer for file uploads
const upload = multer({
    dest: 'uploads/trivy/',
    limits: { fileSize: 500 * 1024 * 1024 }, // 500MB max
});

/**
 * GET /api/trivy/health
 * Health check endpoint
 */
router.get('/health', async (req: Request, res: Response): Promise<void> => {
    try {
        const isHealthy = await trivyService.healthCheck();
        res.json({
            success: true,
            service: 'Trivy Security Scanner',
            status: isHealthy ? 'operational' : 'degraded',
            serverUrl: process.env.TRIVY_SERVER_URL || 'http://localhost:5004',
            timestamp: new Date().toISOString(),
        });
    } catch (error: any) {
        res.status(500).json({
            success: false,
            error: { message: 'Health check failed', details: error.message }
        });
    }
});

/**
 * POST /api/trivy/image
 * Scan Docker image for vulnerabilities
 */
router.post('/image', async (req: Request, res: Response): Promise<void> => {
    try {
        const { imageName, severities, saveToDb } = req.body;

        if (!imageName) {
            res.status(400).json({
                success: false,
                error: { message: 'Image name is required', code: 'MISSING_IMAGE' }
            });
            return;
        }

        console.log(`🐳 Scanning image: ${imageName}`);
        const result = await trivyService.scanImage(imageName, severities);

        // Save to database if requested
        let scanId: string | undefined;
        if (saveToDb !== false) {
            scanId = await trivyService.saveScanToDatabase(result);
        }

        res.json({
            success: true,
            data: { ...result, id: scanId }
        });

    } catch (error: any) {
        console.error('❌ Image scan failed:', error);
        res.status(500).json({
            success: false,
            error: { message: 'Image scan failed', details: error.message }
        });
    }
});

/**
 * POST /api/trivy/filesystem
 * Scan uploaded file/directory for vulnerabilities
 */
router.post('/filesystem', upload.single('file'), async (req: Request, res: Response): Promise<void> => {
    try {
        const { targetPath, severities } = req.body;
        let scanPath = targetPath;

        // If file was uploaded, use that
        if (req.file) {
            scanPath = req.file.path;
        }

        if (!scanPath) {
            res.status(400).json({
                success: false,
                error: { message: 'Target path or file is required' }
            });
            return;
        }

        console.log(`📁 Scanning filesystem: ${scanPath}`);
        const result = await trivyService.scanFilesystem(scanPath, severities);
        const scanId = await trivyService.saveScanToDatabase(result);

        // Cleanup uploaded file
        if (req.file) {
            fs.unlink(req.file.path, () => { });
        }

        res.json({
            success: true,
            data: { ...result, id: scanId }
        });

    } catch (error: any) {
        console.error('❌ Filesystem scan failed:', error);
        res.status(500).json({
            success: false,
            error: { message: 'Filesystem scan failed', details: error.message }
        });
    }
});

/**
 * POST /api/trivy/repository
 * Scan Git repository for vulnerabilities
 */
router.post('/repository', async (req: Request, res: Response): Promise<void> => {
    try {
        const { repoUrl, severities } = req.body;

        if (!repoUrl) {
            res.status(400).json({
                success: false,
                error: { message: 'Repository URL is required' }
            });
            return;
        }

        console.log(`📦 Scanning repository: ${repoUrl}`);
        const result = await trivyService.scanRepository(repoUrl, severities);
        const scanId = await trivyService.saveScanToDatabase(result);

        res.json({
            success: true,
            data: { ...result, id: scanId }
        });

    } catch (error: any) {
        console.error('❌ Repository scan failed:', error);
        res.status(500).json({
            success: false,
            error: { message: 'Repository scan failed', details: error.message }
        });
    }
});

/**
 * POST /api/trivy/secrets
 * Scan for secrets (passwords, API keys, tokens)
 */
router.post('/secrets', upload.single('file'), async (req: Request, res: Response): Promise<void> => {
    try {
        const { targetPath } = req.body;
        let scanPath = targetPath;

        if (req.file) {
            scanPath = req.file.path;
        }

        if (!scanPath) {
            res.status(400).json({
                success: false,
                error: { message: 'Target path or file is required' }
            });
            return;
        }

        console.log(`🔐 Scanning for secrets: ${scanPath}`);
        const result = await trivyService.scanSecrets(scanPath);
        const scanId = await trivyService.saveScanToDatabase(result);

        if (req.file) {
            fs.unlink(req.file.path, () => { });
        }

        res.json({
            success: true,
            data: { ...result, id: scanId }
        });

    } catch (error: any) {
        console.error('❌ Secret scan failed:', error);
        res.status(500).json({
            success: false,
            error: { message: 'Secret scan failed', details: error.message }
        });
    }
});

/**
 * POST /api/trivy/config
 * Scan for misconfigurations (Dockerfile, K8s, Terraform, etc.)
 */
router.post('/config', upload.single('file'), async (req: Request, res: Response): Promise<void> => {
    try {
        const { targetPath } = req.body;
        let scanPath = targetPath;

        if (req.file) {
            scanPath = req.file.path;
        }

        if (!scanPath) {
            res.status(400).json({
                success: false,
                error: { message: 'Target path or file is required' }
            });
            return;
        }

        console.log(`⚙️ Scanning configurations: ${scanPath}`);
        const result = await trivyService.scanConfig(scanPath);
        const scanId = await trivyService.saveScanToDatabase(result);

        if (req.file) {
            fs.unlink(req.file.path, () => { });
        }

        res.json({
            success: true,
            data: { ...result, id: scanId }
        });

    } catch (error: any) {
        console.error('❌ Config scan failed:', error);
        res.status(500).json({
            success: false,
            error: { message: 'Config scan failed', details: error.message }
        });
    }
});

/**
 * POST /api/trivy/licenses
 * Scan for license information
 */
router.post('/licenses', upload.single('file'), async (req: Request, res: Response): Promise<void> => {
    try {
        const { targetPath } = req.body;
        let scanPath = targetPath;

        if (req.file) {
            scanPath = req.file.path;
        }

        if (!scanPath) {
            res.status(400).json({
                success: false,
                error: { message: 'Target path or file is required' }
            });
            return;
        }

        console.log(`📜 Scanning licenses: ${scanPath}`);
        const result = await trivyService.scanLicenses(scanPath);
        const scanId = await trivyService.saveScanToDatabase(result);

        if (req.file) {
            fs.unlink(req.file.path, () => { });
        }

        res.json({
            success: true,
            data: { ...result, id: scanId }
        });

    } catch (error: any) {
        console.error('❌ License scan failed:', error);
        res.status(500).json({
            success: false,
            error: { message: 'License scan failed', details: error.message }
        });
    }
});

/**
 * POST /api/trivy/sbom
 * Generate Software Bill of Materials (SBOM)
 */
router.post('/sbom', async (req: Request, res: Response): Promise<void> => {
    try {
        const { target, format } = req.body;

        if (!target) {
            res.status(400).json({
                success: false,
                error: { message: 'Target is required' }
            });
            return;
        }

        console.log(`📦 Generating SBOM: ${target}`);
        const sbom = await trivyService.generateSBOM(target, format || 'cyclonedx');

        res.json({
            success: true,
            data: sbom
        });

    } catch (error: any) {
        console.error('❌ SBOM generation failed:', error);
        res.status(500).json({
            success: false,
            error: { message: 'SBOM generation failed', details: error.message }
        });
    }
});

/**
 * GET /api/trivy/history
 * Get Trivy scan history
 */
router.get('/history', async (req: Request, res: Response): Promise<void> => {
    try {
        const limit = parseInt(req.query.limit as string) || 50;
        const scans = await trivyService.getTrivyScans(limit);

        res.json({
            success: true,
            data: scans
        });

    } catch (error: any) {
        console.error('❌ Failed to get Trivy history:', error);
        res.status(500).json({
            success: false,
            error: { message: 'Failed to get scan history', details: error.message }
        });
    }
});

/**
 * GET /api/trivy/scan/:scanId
 * Get scan by ID
 */
router.get('/scan/:scanId', async (req: Request, res: Response): Promise<void> => {
    try {
        const { scanId } = req.params;
        const scan = await trivyService.getScanById(scanId);

        if (!scan) {
            res.status(404).json({
                success: false,
                error: { message: 'Scan not found' }
            });
            return;
        }

        res.json({
            success: true,
            data: scan
        });

    } catch (error: any) {
        res.status(500).json({
            success: false,
            error: { message: 'Failed to get scan', details: error.message }
        });
    }
});

/**
 * GET /api/trivy/report/:scanId
 * Download HTML report
 */
router.get('/report/:scanId', async (req: Request, res: Response): Promise<void> => {
    try {
        const { scanId } = req.params;
        const scan = await trivyService.getScanById(scanId);

        if (!scan) {
            res.status(404).json({
                success: false,
                error: { message: 'Scan not found' }
            });
            return;
        }

        const htmlReport = trivyService.generateHtmlReport(scan);

        res.setHeader('Content-Type', 'text/html');
        res.setHeader('Content-Disposition', `attachment; filename="trivy-report-${scanId}.html"`);
        res.send(htmlReport);

    } catch (error: any) {
        res.status(500).json({
            success: false,
            error: { message: 'Failed to generate report', details: error.message }
        });
    }
});

/**
 * ======================
 * GIT REPOSITORY ROUTES
 * ======================
 */

/**
 * POST /api/trivy/private-repository
 * Scan private repository (one-time, without saving)
 */
router.post('/private-repository', async (req: Request, res: Response): Promise<void> => {
    try {
        const { repoUrl, username, password, branch, severities } = req.body;

        if (!repoUrl || !username || !password) {
            res.status(400).json({
                success: false,
                error: { message: 'Repository URL, username, and password are required' }
            });
            return;
        }

        console.log(`🔐 Scanning private repository (one-time): ${repoUrl}`);
        const result = await trivyService.scanPrivateRepository(
            repoUrl,
            username,
            password,
            branch || 'main',
            severities
        );

        // Save to database
        const scanId = await trivyService.saveScanToDatabase(result);

        res.json({
            success: true,
            data: { ...result, id: scanId }
        });

    } catch (error: any) {
        console.error('❌ Private repository scan failed:', error);
        res.status(500).json({
            success: false,
            error: { message: 'Private repository scan failed', details: error.message }
        });
    }
});

/**
 * POST /api/trivy/save-repository
 * Save repository credentials for later use
 */
router.post('/save-repository', async (req: Request, res: Response): Promise<void> => {
    try {
        const { name, repoUrl, username, password, branch } = req.body;
        const userId = (req as any).user?.id || 'anonymous'; // Get from auth middleware

        if (!name || !repoUrl || !username || !password) {
            res.status(400).json({
                success: false,
                error: { message: 'Name, repository URL, username, and password are required' }
            });
            return;
        }

        const repository = await trivyService.saveRepository(
            userId,
            name,
            repoUrl,
            username,
            password,
            branch
        );

        res.json({
            success: true,
            data: repository
        });

    } catch (error: any) {
        console.error('❌ Failed to save repository:', error);
        res.status(500).json({
            success: false,
            error: { message: 'Failed to save repository', details: error.message }
        });
    }
});

/**
 * GET /api/trivy/repositories
 * Get user's saved repositories
 */
router.get('/repositories', async (req: Request, res: Response): Promise<void> => {
    try {
        const userId = (req as any).user?.id || 'anonymous';

        const repositories = await trivyService.getUserRepositories(userId);

        res.json({
            success: true,
            data: repositories
        });

    } catch (error: any) {
        console.error('❌ Failed to get repositories:', error);
        res.status(500).json({
            success: false,
            error: { message: 'Failed to get repositories', details: error.message }
        });
    }
});

/**
 * POST /api/trivy/scan-saved-repository/:id
 * Scan a saved repository by ID
 */
router.post('/scan-saved-repository/:id', async (req: Request, res: Response): Promise<void> => {
    try {
        const { id } = req.params;
        const { severities } = req.body;
        const userId = (req as any).user?.id || 'anonymous';

        const result = await trivyService.scanSavedRepository(id, userId, severities);

        // Save to database
        const scanId = await trivyService.saveScanToDatabase(result);

        res.json({
            success: true,
            data: { ...result, id: scanId }
        });

    } catch (error: any) {
        console.error('❌ Saved repository scan failed:', error);
        res.status(500).json({
            success: false,
            error: { message: 'Failed to scan saved repository', details: error.message }
        });
    }
});

/**
 * DELETE /api/trivy/repository/:id
 * Delete a saved repository
 */
router.delete('/repository/:id', async (req: Request, res: Response): Promise<void> => {
    try {
        const { id } = req.params;
        const userId = (req as any).user?.id || 'anonymous';

        await trivyService.deleteRepository(id, userId);

        res.json({
            success: true,
            message: 'Repository deleted successfully'
        });

    } catch (error: any) {
        console.error('❌ Failed to delete repository:', error);
        res.status(500).json({
            success: false,
            error: { message: 'Failed to delete repository', details: error.message }
        });
    }
});

/**
 * PUT /api/trivy/repository/:id
 * Update a saved repository
 */
router.put('/repository/:id', async (req: Request, res: Response): Promise<void> => {
    try {
        const { id } = req.params;
        const { name, username, password, branch } = req.body;
        const userId = (req as any).user?.id || 'anonymous';

        const repository = await trivyService.updateRepository(id, userId, {
            name,
            username,
            password,
            branch
        });

        res.json({
            success: true,
            data: repository
        });

    } catch (error: any) {
        console.error('❌ Failed to update repository:', error);
        res.status(500).json({
            success: false,
            error: { message: 'Failed to update repository', details: error.message }
        });
    }
});

export default router;
