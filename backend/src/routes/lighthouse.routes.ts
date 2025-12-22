import { Router, Request, Response } from 'express';
import { lighthouseService, LighthouseResult } from '../services/lighthouse.service';
import { emailService } from '../services/email.service';

const router = Router();

/**
 * POST /api/lighthouse/scan
 * Run Lighthouse scan on target URL
 */
router.post('/scan', async (req: Request, res: Response): Promise<void> => {
    try {
        const { targetUrl, categories, throttling, formFactor } = req.body;

        // Validate input
        if (!targetUrl) {
            res.status(400).json({
                success: false,
                error: {
                    message: 'Hedef URL gereklidir',
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
                    message: 'Geçersiz URL formatı. Lütfen geçerli bir URL girin (örn: https://example.com)',
                    code: 'INVALID_URL'
                }
            });
            return;
        }

        console.log(`🔍 Lighthouse scan requested for: ${targetUrl}`);
        console.log(`📋 Categories: ${categories?.join(', ') || 'all'}`);
        console.log(`🖥️ Form Factor: ${formFactor || 'desktop'}`);
        console.log(`⚡ Throttling: ${throttling || 'desktop'}`);

        // Run Lighthouse scan
        const result = await lighthouseService.runScan(targetUrl, {
            categories,
            throttling: throttling || 'desktop',
            formFactor: formFactor || 'desktop',
        });

        console.log(`✅ Lighthouse scan completed`);
        console.log(`📊 Scores - Performance: ${result.categories.performance.score}, Accessibility: ${result.categories.accessibility.score}, Best Practices: ${result.categories.bestPractices.score}, SEO: ${result.categories.seo.score}`);

        // Return results
        res.json({
            success: true,
            data: result
        });

    } catch (error: any) {
        console.error('❌ Lighthouse scan failed:', error);

        res.status(500).json({
            success: false,
            error: {
                message: 'Lighthouse taraması başarısız oldu',
                details: error.message || 'Bilinmeyen hata',
                code: 'SCAN_FAILED'
            }
        });
    }
});

/**
 * POST /api/lighthouse/email-report
 * Send Lighthouse report via email
 */
router.post('/email-report', async (req: Request, res: Response): Promise<void> => {
    try {
        const { email, scanResult, senderName } = req.body;

        // Validate input
        if (!email) {
            res.status(400).json({
                success: false,
                error: {
                    message: 'Email adresi gereklidir',
                    code: 'MISSING_EMAIL'
                }
            });
            return;
        }

        if (!scanResult) {
            res.status(400).json({
                success: false,
                error: {
                    message: 'Tarama sonucu gereklidir',
                    code: 'MISSING_SCAN_RESULT'
                }
            });
            return;
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            res.status(400).json({
                success: false,
                error: {
                    message: 'Geçersiz email formatı',
                    code: 'INVALID_EMAIL'
                }
            });
            return;
        }

        console.log(`📧 Sending Lighthouse report to: ${email}`);

        // Generate HTML report
        const htmlReport = lighthouseService.generateEmailReport(scanResult);

        // Send email
        const emailSent = await emailService.sendEmail({
            to: email,
            subject: `🚀 Lighthouse Raporu - ${scanResult.url}`,
            html: htmlReport,
            text: `Lighthouse Tarama Raporu\n\nURL: ${scanResult.url}\nTarama Zamanı: ${new Date(scanResult.fetchTime).toLocaleString('tr-TR')}\n\nSkorlar:\n- Performance: ${scanResult.categories.performance.score}/100\n- Accessibility: ${scanResult.categories.accessibility.score}/100\n- Best Practices: ${scanResult.categories.bestPractices.score}/100\n- SEO: ${scanResult.categories.seo.score}/100\n\nDetaylı rapor için HTML versiyonunu görüntüleyin.`,
            sentBy: senderName || 'system',
        });

        if (emailSent) {
            console.log(`✅ Lighthouse report email sent to: ${email}`);
            res.json({
                success: true,
                message: 'Rapor başarıyla gönderildi'
            });
        } else {
            throw new Error('Email gönderilemedi');
        }

    } catch (error: any) {
        console.error('❌ Failed to send Lighthouse email report:', error);

        res.status(500).json({
            success: false,
            error: {
                message: 'Email gönderilemedi',
                details: error.message || 'Bilinmeyen hata',
                code: 'EMAIL_FAILED'
            }
        });
    }
});

/**
 * POST /api/lighthouse/save
 * Save Lighthouse scan to database
 */
router.post('/save', async (req: Request, res: Response): Promise<void> => {
    try {
        const { scanResult, userId } = req.body;

        if (!scanResult) {
            res.status(400).json({
                success: false,
                error: { message: 'Tarama sonucu gereklidir', code: 'MISSING_SCAN_RESULT' }
            });
            return;
        }

        const scanId = await lighthouseService.saveScanToDatabase(scanResult, userId);

        res.json({
            success: true,
            data: { scanId },
            message: 'Tarama başarıyla kaydedildi'
        });

    } catch (error: any) {
        console.error('❌ Failed to save Lighthouse scan:', error);
        res.status(500).json({
            success: false,
            error: { message: 'Tarama kaydedilemedi', details: error.message }
        });
    }
});

/**
 * GET /api/lighthouse/history
 * Get Lighthouse scan history
 */
router.get('/history', async (req: Request, res: Response): Promise<void> => {
    try {
        const limit = parseInt(req.query.limit as string) || 50;
        const scans = await lighthouseService.getLighthouseScans(limit);

        res.json({
            success: true,
            data: scans
        });

    } catch (error: any) {
        console.error('❌ Failed to get Lighthouse history:', error);
        res.status(500).json({
            success: false,
            error: { message: 'Geçmiş alınamadı', details: error.message }
        });
    }
});

/**
 * GET /api/lighthouse/scan/:scanId
 * Get Lighthouse scan by ID
 */
router.get('/scan/:scanId', async (req: Request, res: Response): Promise<void> => {
    try {
        const { scanId } = req.params;
        const scan = await lighthouseService.getScanById(scanId);

        if (!scan) {
            res.status(404).json({
                success: false,
                error: { message: 'Tarama bulunamadı', code: 'NOT_FOUND' }
            });
            return;
        }

        res.json({
            success: true,
            data: scan
        });

    } catch (error: any) {
        console.error('❌ Failed to get Lighthouse scan:', error);
        res.status(500).json({
            success: false,
            error: { message: 'Tarama alınamadı', details: error.message }
        });
    }
});

/**
 * GET /api/lighthouse/report/:scanId
 * Download Lighthouse report as HTML
 */
router.get('/report/:scanId', async (req: Request, res: Response): Promise<void> => {
    try {
        const { scanId } = req.params;
        const scan = await lighthouseService.getScanById(scanId);

        if (!scan) {
            res.status(404).json({
                success: false,
                error: { message: 'Tarama bulunamadı', code: 'NOT_FOUND' }
            });
            return;
        }

        const htmlReport = lighthouseService.generateDownloadableReport(scan);

        res.setHeader('Content-Type', 'text/html');
        res.setHeader('Content-Disposition', `attachment; filename="lighthouse-report-${scanId}.html"`);
        res.send(htmlReport);

    } catch (error: any) {
        console.error('❌ Failed to generate Lighthouse report:', error);
        res.status(500).json({
            success: false,
            error: { message: 'Rapor oluşturulamadı', details: error.message }
        });
    }
});

/**
 * DELETE /api/lighthouse/scan/:scanId
 * Delete Lighthouse scan
 */
router.delete('/scan/:scanId', async (req: Request, res: Response): Promise<void> => {
    try {
        const { scanId } = req.params;
        const deleted = await lighthouseService.deleteScan(scanId);

        if (!deleted) {
            res.status(404).json({
                success: false,
                error: { message: 'Tarama bulunamadı veya silinemedi' }
            });
            return;
        }

        res.json({
            success: true,
            message: 'Tarama başarıyla silindi'
        });

    } catch (error: any) {
        console.error('❌ Failed to delete Lighthouse scan:', error);
        res.status(500).json({
            success: false,
            error: { message: 'Tarama silinemedi', details: error.message }
        });
    }
});

/**
 * GET /api/lighthouse/health
 * Health check endpoint
 */
router.get('/health', async (req: Request, res: Response): Promise<void> => {
    res.json({
        success: true,
        service: 'Lighthouse Scan Service',
        status: 'operational',
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

export default router;
