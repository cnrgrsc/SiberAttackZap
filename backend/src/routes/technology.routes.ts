import { Router, Request, Response } from 'express';
import { technologyDetectorService } from '../services/technologyDetector.service';

const router = Router();

/**
 * POST /api/technology/detect
 * Detect technologies used on a website
 */
router.post('/detect', async (req: Request, res: Response): Promise<void> => {
    try {
        const { targetUrl } = req.body;

        // Validate input
        if (!targetUrl) {
            res.status(400).json({
                success: false,
                error: {
                    message: 'Target URL is required',
                    code: 'MISSING_URL'
                }
            });
            return;
        }

        // Validate URL format
        try {
            new URL(targetUrl);
        } catch (urlError) {
            res.status(400).json({
                success: false,
                error: {
                    message: 'Invalid URL format. Please provide a valid URL (e.g., https://example.com)',
                    code: 'INVALID_URL'
                }
            });
            return;
        }

        console.log(`🔍 Technology detection requested for: ${targetUrl}`);

        // Detect technologies
        const result = await technologyDetectorService.detectTechnologies(targetUrl);

        console.log(`✅ Technology detection completed: ${result.technologies.length} technologies found`);

        // Return results
        res.json({
            success: true,
            data: result
        });

    } catch (error) {
        console.error('❌ Technology detection failed:', error);

        res.status(500).json({
            success: false,
            error: {
                message: 'Failed to detect technologies',
                details: error instanceof Error ? error.message : 'Unknown error',
                code: 'DETECTION_FAILED'
            }
        });
    }
});

/**
 * GET /api/technology/health
 * Health check endpoint
 */
router.get('/health', async (req: Request, res: Response): Promise<void> => {
    res.json({
        success: true,
        service: 'Technology Detection Service',
        status: 'operational',
        timestamp: new Date().toISOString()
    });
});

export default router;
