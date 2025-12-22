import lighthouse from 'lighthouse';
import * as chromeLauncher from 'chrome-launcher';
import { PrismaClient } from '@prisma/client';
import { v4 as uuidv4 } from 'uuid';

// Lighthouse result interfaces
interface CategoryResult {
    score: number;
    title: string;
    description?: string;
    auditRefs?: AuditRef[];
}

interface AuditRef {
    id: string;
    weight: number;
    group?: string;
}

interface PerformanceMetrics {
    firstContentfulPaint: MetricValue;
    largestContentfulPaint: MetricValue;
    totalBlockingTime: MetricValue;
    cumulativeLayoutShift: MetricValue;
    speedIndex: MetricValue;
    interactive?: MetricValue;
}

interface MetricValue {
    value: number;
    displayValue: string;
    score: number;
}

interface AuditResult {
    id: string;
    title: string;
    description: string;
    score: number | null;
    displayValue?: string;
    scoreDisplayMode: string;
    category: string;
    details?: any;
}

interface DiagnosticItem {
    title: string;
    description: string;
    savings?: string;
    savingsMs?: number;
    savingsBytes?: number;
    category: string;
    items?: FileItem[];
}

// NEW: File/Resource item for detailed audit info
interface FileItem {
    url: string;
    totalBytes?: number;
    wastedBytes?: number;
    wastedMs?: number;
    wastedPercent?: number;
    label?: string;
}

// NEW: Insight item
interface InsightItem {
    id: string;
    title: string;
    description: string;
    score: number | null;
    severity: 'error' | 'warning' | 'info';
    displayValue?: string;
    savings?: string;
    items?: FileItem[];
}

// NEW: Category-specific audits
interface CategoryAudits {
    failed: AuditResult[];
    passed: AuditResult[];
    notApplicable: AuditResult[];
    manual: AuditResult[];
}

interface LighthouseResult {
    url: string;
    fetchTime: string;
    device: 'mobile' | 'desktop';
    categories: {
        performance: CategoryResult;
        accessibility: CategoryResult;
        bestPractices: CategoryResult;
        seo: CategoryResult;
    };
    metrics: PerformanceMetrics;
    audits: AuditResult[];
    diagnostics: DiagnosticItem[];
    insights: InsightItem[];
    categoryAudits: {
        performance: CategoryAudits;
        accessibility: CategoryAudits;
        bestPractices: CategoryAudits;
        seo: CategoryAudits;
    };
    treemapData?: any;
    filmstrip?: any[];
    finalScreenshot?: string;
    runWarnings: string[];
}

interface LighthouseScanOptions {
    categories?: string[];
    throttling?: 'mobile' | 'desktop' | 'none';
    formFactor?: 'mobile' | 'desktop';
}

class LighthouseService {
    private prisma = new PrismaClient();

    private chromeFlags = [
        '--headless',
        '--disable-gpu',
        '--no-sandbox',
        '--disable-dev-shm-usage',
        '--ignore-certificate-errors', // İç ağ için SSL bypass
        '--allow-insecure-localhost',
        '--disable-web-security',
    ];

    constructor() {
        console.log('🚀 Lighthouse Service initialized');
    }

    /**
     * Run Lighthouse scan on target URL
     */
    async runScan(targetUrl: string, options: LighthouseScanOptions = {}): Promise<LighthouseResult> {
        console.log(`🔍 Starting Lighthouse scan for: ${targetUrl}`);

        let chrome: chromeLauncher.LaunchedChrome | null = null;

        try {
            // Launch Chrome
            console.log('🌐 Launching Chrome...');
            chrome = await chromeLauncher.launch({
                chromeFlags: this.chromeFlags,
                logLevel: 'silent',
            });

            console.log(`✅ Chrome launched on port: ${chrome.port}`);

            const device = options.formFactor || 'desktop';
            const isMobile = device === 'mobile';

            // Configure Lighthouse options
            const lighthouseOptions: any = {
                logLevel: 'silent',
                output: 'json',
                port: chrome.port,
                onlyCategories: options.categories || ['performance', 'accessibility', 'best-practices', 'seo'],
                formFactor: device,
                screenEmulation: isMobile ? {
                    mobile: true,
                    width: 412,
                    height: 823,
                    deviceScaleFactor: 1.75,
                    disabled: false,
                } : {
                    mobile: false,
                    width: 1350,
                    height: 940,
                    deviceScaleFactor: 1,
                    disabled: false,
                },
                throttling: this.getThrottlingConfig(options.throttling || device),
                // İç ağ için SSL hataları yoksay
                extraHeaders: {
                    'Accept-Language': 'tr-TR,tr;q=0.9,en;q=0.8',
                },
            };

            // Run Lighthouse
            console.log(`📊 Running Lighthouse audit (${device})...`);
            const runnerResult = await lighthouse(targetUrl, lighthouseOptions);

            if (!runnerResult || !runnerResult.lhr) {
                throw new Error('Lighthouse taraması başarısız oldu - sonuç boş');
            }

            const lhr = runnerResult.lhr;
            console.log(`✅ Lighthouse audit completed for: ${lhr.finalDisplayedUrl}`);

            // Extract results with device info
            const result = this.extractResults(lhr, device);

            return result;

        } catch (error: any) {
            console.error('❌ Lighthouse scan failed:', error.message || error);
            throw new Error(`Lighthouse taraması başarısız: ${error.message || 'Bilinmeyen hata'}`);
        } finally {
            // Always close Chrome
            if (chrome) {
                console.log('🔒 Closing Chrome...');
                await chrome.kill();
            }
        }
    }

    /**
     * Get throttling configuration
     */
    private getThrottlingConfig(throttling: string): any {
        switch (throttling) {
            case 'mobile':
                return {
                    rttMs: 150,
                    throughputKbps: 1638.4,
                    cpuSlowdownMultiplier: 4,
                    requestLatencyMs: 0,
                    downloadThroughputKbps: 1638.4,
                    uploadThroughputKbps: 675,
                };
            case 'desktop':
                return {
                    rttMs: 40,
                    throughputKbps: 10240,
                    cpuSlowdownMultiplier: 1,
                    requestLatencyMs: 0,
                    downloadThroughputKbps: 10240,
                    uploadThroughputKbps: 10240,
                };
            case 'none':
            default:
                return {
                    rttMs: 0,
                    throughputKbps: 0,
                    cpuSlowdownMultiplier: 1,
                    requestLatencyMs: 0,
                    downloadThroughputKbps: 0,
                    uploadThroughputKbps: 0,
                };
        }
    }

    /**
     * Extract and format Lighthouse results
     */
    private extractResults(lhr: any, device: 'mobile' | 'desktop' = 'desktop'): LighthouseResult {
        // Extract category scores
        const categories = {
            performance: this.extractCategory(lhr.categories?.performance),
            accessibility: this.extractCategory(lhr.categories?.accessibility),
            bestPractices: this.extractCategory(lhr.categories?.['best-practices']),
            seo: this.extractCategory(lhr.categories?.seo),
        };

        // Extract performance metrics
        const metrics = this.extractMetrics(lhr.audits);

        // Extract audits
        const audits = this.extractAudits(lhr.audits, lhr.categories);

        // Extract diagnostics with file details
        const diagnostics = this.extractDiagnostics(lhr.audits);

        // Extract insights (opportunities and diagnostics with details)
        const insights = this.extractInsights(lhr.audits);

        // Extract category-specific audits
        const categoryAudits = {
            performance: this.extractCategoryAudits(lhr.audits, lhr.categories?.performance),
            accessibility: this.extractCategoryAudits(lhr.audits, lhr.categories?.accessibility),
            bestPractices: this.extractCategoryAudits(lhr.audits, lhr.categories?.['best-practices']),
            seo: this.extractCategoryAudits(lhr.audits, lhr.categories?.seo),
        };

        // Extract treemap data
        const treemapData = this.extractTreemapData(lhr.audits);

        // Extract filmstrip
        const filmstrip = this.extractFilmstrip(lhr.audits);

        // Get final screenshot if available
        const finalScreenshot = lhr.audits?.['final-screenshot']?.details?.data || undefined;

        return {
            url: lhr.finalDisplayedUrl || lhr.requestedUrl,
            fetchTime: lhr.fetchTime || new Date().toISOString(),
            device,
            categories,
            metrics,
            audits,
            diagnostics,
            insights,
            categoryAudits,
            treemapData,
            filmstrip,
            finalScreenshot,
            runWarnings: lhr.runWarnings || [],
        };
    }

    /**
     * Extract category data
     */
    private extractCategory(category: any): CategoryResult {
        if (!category) {
            return { score: 0, title: 'Unknown', description: '' };
        }

        return {
            score: Math.round((category.score || 0) * 100),
            title: category.title || 'Unknown',
            description: category.description || '',
            auditRefs: category.auditRefs?.map((ref: any) => ({
                id: ref.id,
                weight: ref.weight,
                group: ref.group,
            })),
        };
    }

    /**
     * Extract performance metrics
     */
    private extractMetrics(audits: any): PerformanceMetrics {
        const getMetric = (id: string): MetricValue => {
            const audit = audits?.[id];
            return {
                value: audit?.numericValue || 0,
                displayValue: audit?.displayValue || 'N/A',
                score: Math.round((audit?.score || 0) * 100),
            };
        };

        return {
            firstContentfulPaint: getMetric('first-contentful-paint'),
            largestContentfulPaint: getMetric('largest-contentful-paint'),
            totalBlockingTime: getMetric('total-blocking-time'),
            cumulativeLayoutShift: getMetric('cumulative-layout-shift'),
            speedIndex: getMetric('speed-index'),
            interactive: getMetric('interactive'),
        };
    }

    /**
     * Extract audit results
     */
    private extractAudits(audits: any, categories: any): AuditResult[] {
        if (!audits) return [];

        const results: AuditResult[] = [];
        const categoryMap: { [key: string]: string } = {};

        // Build audit to category mapping
        if (categories) {
            Object.entries(categories).forEach(([catKey, catValue]: [string, any]) => {
                catValue?.auditRefs?.forEach((ref: any) => {
                    categoryMap[ref.id] = catKey;
                });
            });
        }

        // Important audits to include
        const importantAudits = [
            'first-contentful-paint',
            'largest-contentful-paint',
            'total-blocking-time',
            'cumulative-layout-shift',
            'speed-index',
            'uses-text-compression',
            'uses-responsive-images',
            'offscreen-images',
            'render-blocking-resources',
            'unused-javascript',
            'unused-css-rules',
            'modern-image-formats',
            'uses-optimized-images',
            'image-alt',
            'button-name',
            'link-name',
            'color-contrast',
            'meta-description',
            'document-title',
            'viewport',
            'robots-txt',
            'is-on-https',
            'csp-xss',
            'no-vulnerable-libraries',
        ];

        Object.entries(audits).forEach(([id, audit]: [string, any]) => {
            // Include if it's an important audit or has a low score
            const isImportant = importantAudits.includes(id);
            const hasLowScore = audit.score !== null && audit.score < 1;

            if (isImportant || hasLowScore) {
                results.push({
                    id,
                    title: audit.title || id,
                    description: audit.description || '',
                    score: audit.score !== null ? Math.round(audit.score * 100) : null,
                    displayValue: audit.displayValue,
                    scoreDisplayMode: audit.scoreDisplayMode || 'numeric',
                    category: categoryMap[id] || 'other',
                    details: audit.details?.type === 'opportunity' || audit.details?.type === 'table'
                        ? {
                            type: audit.details.type,
                            overallSavingsMs: audit.details.overallSavingsMs,
                            overallSavingsBytes: audit.details.overallSavingsBytes,
                            itemCount: audit.details.items?.length || 0,
                        }
                        : undefined,
                });
            }
        });

        // Sort by score (lowest first)
        return results.sort((a, b) => {
            if (a.score === null) return 1;
            if (b.score === null) return -1;
            return a.score - b.score;
        });
    }

    /**
     * Extract diagnostics and opportunities
     */
    private extractDiagnostics(audits: any): DiagnosticItem[] {
        if (!audits) return [];

        const diagnostics: DiagnosticItem[] = [];

        const diagnosticAudits = [
            { id: 'unused-javascript', category: 'JavaScript' },
            { id: 'unused-css-rules', category: 'CSS' },
            { id: 'render-blocking-resources', category: 'Render' },
            { id: 'offscreen-images', category: 'Images' },
            { id: 'uses-responsive-images', category: 'Images' },
            { id: 'modern-image-formats', category: 'Images' },
            { id: 'uses-text-compression', category: 'Network' },
            { id: 'uses-long-cache-ttl', category: 'Cache' },
            { id: 'total-byte-weight', category: 'Network' },
            { id: 'dom-size', category: 'DOM' },
            { id: 'mainthread-work-breakdown', category: 'JavaScript' },
            { id: 'bootup-time', category: 'JavaScript' },
            { id: 'font-display', category: 'Fonts' },
        ];

        diagnosticAudits.forEach(({ id, category }) => {
            const audit = audits[id];
            if (audit && audit.score !== null && audit.score < 1) {
                let savings = '';
                if (audit.details?.overallSavingsMs) {
                    savings = `${Math.round(audit.details.overallSavingsMs)} ms tasarruf`;
                } else if (audit.details?.overallSavingsBytes) {
                    savings = `${Math.round(audit.details.overallSavingsBytes / 1024)} KB tasarruf`;
                }

                diagnostics.push({
                    title: audit.title,
                    description: audit.description,
                    savings,
                    savingsMs: audit.details?.overallSavingsMs,
                    savingsBytes: audit.details?.overallSavingsBytes,
                    category,
                    items: this.extractFileItems(audit.details?.items),
                });
            }
        });

        return diagnostics;
    }

    /**
     * Extract insights (opportunities and diagnostics with details)
     */
    private extractInsights(audits: any): InsightItem[] {
        if (!audits) return [];

        const insights: InsightItem[] = [];

        const insightAudits = [
            // Performance insights
            'forced-reflow',
            'lcp-lazy-loaded',
            'network-rtt',
            'network-server-latency',
            'uses-long-cache-ttl',
            'font-display',
            'uses-responsive-images',
            'modern-image-formats',
            'uses-http2',
            'legacy-javascript',
            'layout-shift-elements',
            'largest-contentful-paint-element',
            'third-party-summary',
            'unused-javascript',
            'unused-css-rules',
            'render-blocking-resources',
            'unminified-javascript',
            'unminified-css',
            'uses-text-compression',
            'uses-optimized-images',
            'offscreen-images',
            'server-response-time',
            'redirects',
            'mainthread-work-breakdown',
            'bootup-time',
            'dom-size',
            'critical-request-chains',
            'total-byte-weight',
            'long-tasks',
            'user-timings',
            'preload-lcp-image',
            'prioritize-lcp-image',
            'efficient-animated-content',
        ];

        insightAudits.forEach(id => {
            const audit = audits[id];
            if (audit && (audit.score === null || audit.score < 1)) {
                let savings = '';
                if (audit.details?.overallSavingsMs) {
                    savings = `${Math.round(audit.details.overallSavingsMs)} ms tasarruf`;
                } else if (audit.details?.overallSavingsBytes) {
                    savings = `${Math.round(audit.details.overallSavingsBytes / 1024)} KB tasarruf`;
                }

                let severity: 'error' | 'warning' | 'info' = 'info';
                if (audit.score === null) {
                    severity = 'info';
                } else if (audit.score < 0.5) {
                    severity = 'error';
                } else if (audit.score < 0.9) {
                    severity = 'warning';
                }

                insights.push({
                    id,
                    title: audit.title,
                    description: audit.description || '',
                    score: audit.score !== null ? Math.round(audit.score * 100) : null,
                    severity,
                    displayValue: audit.displayValue,
                    savings: savings || undefined,
                    items: this.extractFileItems(audit.details?.items),
                });
            }
        });

        // Sort by severity (error first) then by score
        return insights.sort((a, b) => {
            const severityOrder = { error: 0, warning: 1, info: 2 };
            if (severityOrder[a.severity] !== severityOrder[b.severity]) {
                return severityOrder[a.severity] - severityOrder[b.severity];
            }
            return (a.score || 0) - (b.score || 0);
        });
    }

    /**
     * Extract file/resource items from audit details
     */
    private extractFileItems(items: any[]): FileItem[] {
        if (!items || !Array.isArray(items)) return [];

        return items.slice(0, 20).map(item => ({
            url: item.url || item.source?.url || item.node?.snippet || 'Unknown',
            totalBytes: item.totalBytes,
            wastedBytes: item.wastedBytes,
            wastedMs: item.wastedMs,
            wastedPercent: item.wastedPercent,
            label: item.label || item.groupLabel || item.node?.nodeLabel,
        })).filter(item => item.url !== 'Unknown');
    }

    /**
     * Extract category-specific audits (failed, passed, notApplicable, manual)
     */
    private extractCategoryAudits(audits: any, category: any): CategoryAudits {
        const result: CategoryAudits = {
            failed: [],
            passed: [],
            notApplicable: [],
            manual: [],
        };

        if (!category?.auditRefs) return result;

        category.auditRefs.forEach((ref: any) => {
            const audit = audits[ref.id];
            if (!audit) return;

            const auditResult: AuditResult = {
                id: ref.id,
                title: audit.title || ref.id,
                description: audit.description || '',
                score: audit.score !== null ? Math.round(audit.score * 100) : null,
                displayValue: audit.displayValue,
                scoreDisplayMode: audit.scoreDisplayMode || 'numeric',
                category: category.id || '',
                details: audit.details ? {
                    type: audit.details.type,
                    items: this.extractFileItems(audit.details.items),
                    overallSavingsMs: audit.details.overallSavingsMs,
                    overallSavingsBytes: audit.details.overallSavingsBytes,
                } : undefined,
            };

            if (audit.scoreDisplayMode === 'notApplicable') {
                result.notApplicable.push(auditResult);
            } else if (audit.scoreDisplayMode === 'manual') {
                result.manual.push(auditResult);
            } else if (audit.score === null) {
                result.notApplicable.push(auditResult);
            } else if (audit.score >= 0.9) {
                result.passed.push(auditResult);
            } else {
                result.failed.push(auditResult);
            }
        });

        // Sort failed by score ascending
        result.failed.sort((a, b) => (a.score || 0) - (b.score || 0));

        return result;
    }

    /**
     * Extract treemap data for JavaScript bundle analysis
     */
    private extractTreemapData(audits: any): any {
        const scriptTreemap = audits?.['script-treemap-data'];
        if (scriptTreemap?.details?.nodes) {
            return {
                type: 'treemap',
                nodes: scriptTreemap.details.nodes.slice(0, 50).map((node: any) => ({
                    name: node.name || 'Unknown',
                    resourceBytes: node.resourceBytes || 0,
                    unusedBytes: node.unusedBytes || 0,
                })),
            };
        }
        return undefined;
    }

    /**
     * Extract filmstrip/screenshots timeline
     */
    private extractFilmstrip(audits: any): any[] {
        const filmstrip = audits?.['screenshot-thumbnails']?.details?.items;
        if (filmstrip && Array.isArray(filmstrip)) {
            return filmstrip.map((item: any) => ({
                timing: item.timing,
                timestamp: item.timestamp,
                data: item.data,
            }));
        }
        return [];
    }

    /**
     * Generate email-friendly HTML report
     */
    generateEmailReport(result: LighthouseResult): string {
        const getScoreColor = (score: number): string => {
            if (score >= 90) return '#0cce6b';
            if (score >= 50) return '#ffa400';
            return '#ff4e42';
        };

        const getScoreEmoji = (score: number): string => {
            if (score >= 90) return '🟢';
            if (score >= 50) return '🟠';
            return '🔴';
        };

        const formatBytes = (bytes?: number): string => {
            if (!bytes) return '';
            if (bytes < 1024) return `${bytes} B`;
            if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
            return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
        };

        // Generate insights HTML
        const insightsHtml = result.insights && result.insights.length > 0 ? `
        <div class="section-title">💡 Insights (Fırsatlar)</div>
        ${result.insights.slice(0, 15).map(insight => `
            <div class="insight ${insight.severity}">
                <div class="insight-header">
                    <span class="severity-badge ${insight.severity}">${insight.severity === 'error' ? '🔴' : insight.severity === 'warning' ? '🟠' : '🔵'}</span>
                    <span class="insight-title">${insight.title}</span>
                    ${insight.savings ? `<span class="savings">${insight.savings}</span>` : ''}
                    ${insight.displayValue ? `<span class="display-value">${insight.displayValue}</span>` : ''}
                </div>
                ${insight.items && insight.items.length > 0 ? `
                    <div class="items-list">
                        <table>
                            <thead>
                                <tr>
                                    <th>Dosya</th>
                                    <th>Boyut</th>
                                    <th>İsraf</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${insight.items.slice(0, 8).map(item => `
                                    <tr>
                                        <td class="file-url">${item.url?.split('/').pop() || item.label || 'Unknown'}</td>
                                        <td>${formatBytes(item.totalBytes)}</td>
                                        <td class="wasted">${formatBytes(item.wastedBytes)}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                ` : ''}
            </div>
        `).join('')}
        ` : '';

        // Generate diagnostics HTML
        const diagnosticsHtml = result.diagnostics && result.diagnostics.length > 0 ? `
        <div class="section-title">⚠️ Diagnostics (Teşhisler)</div>
        ${result.diagnostics.slice(0, 15).map(d => `
            <div class="diagnostic">
                <div class="diagnostic-title">${d.title}</div>
                ${d.savings ? `<div class="diagnostic-savings">💡 ${d.savings}</div>` : ''}
                ${d.items && d.items.length > 0 ? `
                    <div class="items-list">
                        <ul>
                            ${d.items.slice(0, 5).map(item => `
                                <li>${item.url?.split('/').pop() || item.label || 'Unknown'}${item.wastedBytes ? ` - ${formatBytes(item.wastedBytes)}` : ''}</li>
                            `).join('')}
                        </ul>
                    </div>
                ` : ''}
            </div>
        `).join('')}
        ` : '';

        // Generate category audits HTML
        const generateCategoryAuditHtml = (title: string, emoji: string, audits: CategoryAudits | undefined) => {
            if (!audits) return '';

            const failedHtml = audits.failed.length > 0 ? `
                <div class="audit-section failed">
                    <div class="audit-section-title">❌ Başarısız (${audits.failed.length})</div>
                    ${audits.failed.slice(0, 10).map(audit => `
                        <div class="audit-item failed">
                            <span class="audit-name">${audit.title}</span>
                            ${audit.displayValue ? `<span class="audit-value">${audit.displayValue}</span>` : ''}
                        </div>
                    `).join('')}
                </div>
            ` : '';

            const passedHtml = audits.passed.length > 0 ? `
                <div class="audit-section passed">
                    <div class="audit-section-title">✅ Başarılı (${audits.passed.length})</div>
                    <div class="passed-list">
                        ${audits.passed.slice(0, 15).map(audit => `
                            <span class="passed-item">${audit.title}</span>
                        `).join('')}
                    </div>
                </div>
            ` : '';

            return `
                <div class="category-audits">
                    <div class="category-title">${emoji} ${title}</div>
                    ${failedHtml}
                    ${passedHtml}
                </div>
            `;
        };

        const accessibilityAuditsHtml = generateCategoryAuditHtml('Accessibility Denetimleri', '♿', result.categoryAudits?.accessibility);
        const bestPracticesAuditsHtml = generateCategoryAuditHtml('Best Practices Denetimleri', '🛡️', result.categoryAudits?.bestPractices);
        const seoAuditsHtml = generateCategoryAuditHtml('SEO Denetimleri', '🔍', result.categoryAudits?.seo);
        const performanceAuditsHtml = generateCategoryAuditHtml('Performance Denetimleri', '⚡', result.categoryAudits?.performance);

        return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Lighthouse Raporu - ${result.url}</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: 'Segoe UI', Arial, sans-serif; background: #1a1a1a; color: #e0e0e0; padding: 20px; margin: 0; }
        .container { max-width: 1000px; margin: 0 auto; background: #2d2d2d; border-radius: 12px; padding: 30px; }
        .header { text-align: center; margin-bottom: 30px; border-bottom: 2px solid #444; padding-bottom: 20px; }
        .header h1 { color: #4fc3f7; margin: 0 0 10px 0; }
        .header .url { color: #888; font-size: 14px; word-break: break-all; }
        .device-badge { display: inline-block; background: #4fc3f7; color: #000; padding: 4px 12px; border-radius: 4px; font-size: 12px; margin-top: 10px; }
        
        .scores { display: flex; justify-content: space-around; margin: 30px 0; flex-wrap: wrap; }
        .score-circle { text-align: center; margin: 10px; min-width: 120px; }
        .score-value { font-size: 42px; font-weight: bold; }
        .score-label { font-size: 14px; color: #888; margin-top: 5px; }
        
        .section-title { color: #4fc3f7; font-size: 20px; margin: 35px 0 15px 0; border-bottom: 1px solid #444; padding-bottom: 10px; }
        
        .metrics { background: #252525; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .metric-row { display: flex; justify-content: space-between; padding: 12px 0; border-bottom: 1px solid #333; }
        .metric-row:last-child { border-bottom: none; }
        .metric-name { color: #888; }
        .metric-value { font-weight: bold; }
        
        .insight { background: #252525; padding: 15px; margin: 12px 0; border-radius: 8px; border-left: 4px solid #ffa400; }
        .insight.error { border-left-color: #ff4e42; }
        .insight.warning { border-left-color: #ffa400; }
        .insight.info { border-left-color: #4fc3f7; }
        .insight-header { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
        .insight-title { font-weight: bold; flex: 1; }
        .savings { background: #0cce6b33; color: #0cce6b; padding: 2px 8px; border-radius: 4px; font-size: 12px; }
        .display-value { color: #888; font-size: 12px; }
        
        .diagnostic { background: #252525; padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #ffa400; }
        .diagnostic-title { font-weight: bold; margin-bottom: 5px; }
        .diagnostic-savings { color: #0cce6b; font-size: 12px; margin-top: 5px; }
        
        .items-list { margin-top: 10px; background: #1a1a1a; border-radius: 4px; padding: 10px; }
        .items-list table { width: 100%; border-collapse: collapse; font-size: 12px; }
        .items-list th { text-align: left; color: #888; padding: 5px 10px; border-bottom: 1px solid #333; }
        .items-list td { padding: 5px 10px; border-bottom: 1px solid #222; }
        .items-list .file-url { max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .items-list .wasted { color: #ff4e42; }
        .items-list ul { margin: 5px 0; padding-left: 20px; }
        .items-list li { color: #aaa; font-size: 12px; margin: 3px 0; }
        
        .category-audits { margin: 20px 0; background: #252525; border-radius: 8px; padding: 20px; }
        .category-title { font-size: 18px; font-weight: bold; margin-bottom: 15px; color: #4fc3f7; }
        .audit-section { margin: 15px 0; }
        .audit-section-title { font-size: 14px; margin-bottom: 10px; }
        .audit-item { padding: 8px 12px; background: #1a1a1a; border-radius: 4px; margin: 5px 0; display: flex; justify-content: space-between; align-items: center; }
        .audit-item.failed { border-left: 3px solid #ff4e42; }
        .audit-name { flex: 1; font-size: 13px; }
        .audit-value { color: #888; font-size: 12px; }
        .passed-list { display: flex; flex-wrap: wrap; gap: 8px; }
        .passed-item { background: #0cce6b22; color: #0cce6b; padding: 4px 10px; border-radius: 4px; font-size: 12px; }
        
        .footer { text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #444; color: #666; font-size: 12px; }
        
        @media print {
            body { background: #fff; color: #000; }
            .container { background: #fff; box-shadow: none; }
            .score-value { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 Lighthouse Tarama Raporu</h1>
            <div class="url">${result.url}</div>
            <div class="device-badge">📱 ${result.device?.toUpperCase() || 'DESKTOP'}</div>
            <div style="color: #666; font-size: 12px; margin-top: 10px;">
                Tarama Zamanı: ${new Date(result.fetchTime).toLocaleString('tr-TR')}
            </div>
        </div>

        <div class="scores">
            <div class="score-circle">
                <div class="score-value" style="color: ${getScoreColor(result.categories.performance.score)}">
                    ${getScoreEmoji(result.categories.performance.score)} ${result.categories.performance.score}
                </div>
                <div class="score-label">Performance</div>
            </div>
            <div class="score-circle">
                <div class="score-value" style="color: ${getScoreColor(result.categories.accessibility.score)}">
                    ${getScoreEmoji(result.categories.accessibility.score)} ${result.categories.accessibility.score}
                </div>
                <div class="score-label">Accessibility</div>
            </div>
            <div class="score-circle">
                <div class="score-value" style="color: ${getScoreColor(result.categories.bestPractices.score)}">
                    ${getScoreEmoji(result.categories.bestPractices.score)} ${result.categories.bestPractices.score}
                </div>
                <div class="score-label">Best Practices</div>
            </div>
            <div class="score-circle">
                <div class="score-value" style="color: ${getScoreColor(result.categories.seo.score)}">
                    ${getScoreEmoji(result.categories.seo.score)} ${result.categories.seo.score}
                </div>
                <div class="score-label">SEO</div>
            </div>
        </div>

        <div class="section-title">📊 Performans Metrikleri</div>
        <div class="metrics">
            <div class="metric-row">
                <span class="metric-name">First Contentful Paint (FCP)</span>
                <span class="metric-value" style="color: ${getScoreColor(result.metrics.firstContentfulPaint.score)}">${result.metrics.firstContentfulPaint.displayValue}</span>
            </div>
            <div class="metric-row">
                <span class="metric-name">Largest Contentful Paint (LCP)</span>
                <span class="metric-value" style="color: ${getScoreColor(result.metrics.largestContentfulPaint.score)}">${result.metrics.largestContentfulPaint.displayValue}</span>
            </div>
            <div class="metric-row">
                <span class="metric-name">Total Blocking Time (TBT)</span>
                <span class="metric-value" style="color: ${getScoreColor(result.metrics.totalBlockingTime.score)}">${result.metrics.totalBlockingTime.displayValue}</span>
            </div>
            <div class="metric-row">
                <span class="metric-name">Cumulative Layout Shift (CLS)</span>
                <span class="metric-value" style="color: ${getScoreColor(result.metrics.cumulativeLayoutShift.score)}">${result.metrics.cumulativeLayoutShift.displayValue}</span>
            </div>
            <div class="metric-row">
                <span class="metric-name">Speed Index</span>
                <span class="metric-value" style="color: ${getScoreColor(result.metrics.speedIndex.score)}">${result.metrics.speedIndex.displayValue}</span>
            </div>
            ${result.metrics.interactive ? `
            <div class="metric-row">
                <span class="metric-name">Time to Interactive (TTI)</span>
                <span class="metric-value" style="color: ${getScoreColor(result.metrics.interactive.score)}">${result.metrics.interactive.displayValue}</span>
            </div>
            ` : ''}
        </div>

        ${insightsHtml}
        ${diagnosticsHtml}
        ${performanceAuditsHtml}
        ${accessibilityAuditsHtml}
        ${bestPracticesAuditsHtml}
        ${seoAuditsHtml}

        <div class="footer">
            <p>Bu rapor İBB Güvenlik Tarama Platformu tarafından oluşturulmuştur.</p>
            <p>Lighthouse v13 | ${new Date().toLocaleDateString('tr-TR')} | ${result.device?.toUpperCase() || 'DESKTOP'}</p>
        </div>
    </div>
</body>
</html>
        `;
    }

    /**
     * Save Lighthouse scan to database
     */
    async saveScanToDatabase(result: LighthouseResult, userId?: string): Promise<string> {
        const scanId = uuidv4();

        try {
            await this.prisma.scan.create({
                data: {
                    id: scanId,
                    name: `Lighthouse - ${new URL(result.url).hostname}`,
                    targetUrl: result.url,
                    scanType: 'LIGHTHOUSE',
                    status: 'COMPLETED',
                    startedAt: new Date(result.fetchTime),
                    completedAt: new Date(),
                    createdBy: userId,
                    metadata: JSON.parse(JSON.stringify({
                        device: result.device,
                        categories: result.categories,
                        metrics: result.metrics,
                        audits: result.audits,
                        diagnostics: result.diagnostics,
                        insights: result.insights,
                        categoryAudits: result.categoryAudits,
                        finalScreenshot: result.finalScreenshot,
                        runWarnings: result.runWarnings,
                    })),
                    environment: 'LIGHTHOUSE',
                },
            });

            console.log(`✅ Lighthouse scan saved to database: ${scanId}`);
            return scanId;
        } catch (error) {
            console.error('❌ Failed to save Lighthouse scan:', error);
            throw error;
        }
    }

    /**
     * Get Lighthouse scan history
     */
    async getLighthouseScans(limit: number = 50): Promise<any[]> {
        try {
            const scans = await this.prisma.scan.findMany({
                where: {
                    scanType: 'LIGHTHOUSE',
                },
                orderBy: {
                    startedAt: 'desc',
                },
                take: limit,
                select: {
                    id: true,
                    name: true,
                    targetUrl: true,
                    status: true,
                    startedAt: true,
                    completedAt: true,
                    createdBy: true,
                    metadata: true,
                },
            });

            return scans.map(scan => ({
                ...scan,
                categories: (scan.metadata as any)?.categories,
                device: (scan.metadata as any)?.device,
            }));
        } catch (error) {
            console.error('❌ Failed to get Lighthouse scans:', error);
            return [];
        }
    }

    /**
     * Get Lighthouse scan by ID
     */
    async getScanById(scanId: string): Promise<any | null> {
        try {
            const scan = await this.prisma.scan.findUnique({
                where: { id: scanId },
            });

            if (!scan || scan.scanType !== 'LIGHTHOUSE') {
                return null;
            }

            return {
                ...scan,
                ...(scan.metadata as any),
            };
        } catch (error) {
            console.error('❌ Failed to get Lighthouse scan:', error);
            return null;
        }
    }

    /**
     * Generate downloadable HTML report
     */
    generateDownloadableReport(result: LighthouseResult): string {
        return this.generateEmailReport(result);
    }

    /**
     * Delete Lighthouse scan
     */
    async deleteScan(scanId: string): Promise<boolean> {
        try {
            await this.prisma.scan.delete({
                where: { id: scanId },
            });
            console.log(`✅ Lighthouse scan deleted: ${scanId}`);
            return true;
        } catch (error) {
            console.error('❌ Failed to delete Lighthouse scan:', error);
            return false;
        }
    }
}

// Export singleton instance
export const lighthouseService = new LighthouseService();
export { LighthouseResult, LighthouseScanOptions, CategoryResult, PerformanceMetrics, AuditResult, DiagnosticItem };
