interface ZapSessionData {
  sites: any[];
  alerts: any[];
  urls: string[];
  targetUrl: string;
  scanDate: Date;
  scanType: string;
}

export class ZapReportGenerator {
  
  async generateZapSessionReport(sessionData: ZapSessionData): Promise<string> {
    try {
      const vulnerabilities = sessionData.alerts.map((alert: any, index: number) => ({
        id: alert.alertId || alert.id || index.toString(),
        name: alert.name || alert.alert || 'Unknown Vulnerability',
        description: alert.description || 'No description available',
        severity: this.mapSeverity(alert.severity || alert.risk || 'LOW'),
        confidence: alert.confidence || 'Medium',
        solution: alert.solution || 'No solution provided',
        reference: alert.reference || '',
        url: alert.url || '',
        param: alert.param || '',
        attack: alert.attack || '',
        evidence: alert.evidence || ''
      }));

      const statistics = this.calculateStatistics(vulnerabilities, sessionData.urls);
      const scanDate = sessionData.scanDate.toLocaleDateString('tr-TR');
      const scanTime = sessionData.scanDate.toLocaleTimeString('tr-TR');
      const mainTarget = this.extractMainTarget(sessionData.targetUrl, sessionData.sites);

      return this.generateHtmlTemplate({
        targetUrl: mainTarget,
        scanDate,
        scanTime,
        scanType: sessionData.scanType,
        vulnerabilities,
        urls: sessionData.urls,
        statistics,
        sites: sessionData.sites
      });

    } catch (error) {
      console.error('❌ ZAP session report generation error:', error);
      throw new Error(`ZAP session report generation failed: ${error}`);
    }
  }

  async generateManualScanReport(data: any): Promise<string> {
    try {
      
      const vulnerabilities = data.scanResults?.map((result: any, index: number) => ({
        id: result.id || index.toString(),
        name: `${result.tool} - ${result.command}`,
        description: result.findings?.join(', ') || 'No findings',
        severity: result.severity || 'low',
        confidence: 'Medium',
        solution: result.recommendations?.join(', ') || 'No recommendations',
        reference: '',
        url: data.target || '',
        param: '',
        attack: result.command || '',
        evidence: result.findings?.join('\n') || '',
        duration: result.duration || 0,
        timestamp: result.timestamp || new Date().toISOString()
      })) || [];

      const httpRequests = data.interceptedRequests?.map((req: any) => ({
        method: req.method || 'GET',
        url: req.url || '',
        status: req.status || 0,
        timestamp: req.timestamp || new Date().toISOString(),
        duration: req.duration || 0,
        headers: req.headers || {},
        body: req.body || ''
      })) || [];

      const statistics = {
        totalVulnerabilities: vulnerabilities.length,
        criticalCount: vulnerabilities.filter((v: any) => v.severity === 'critical').length,
        highCount: vulnerabilities.filter((v: any) => v.severity === 'high').length,
        mediumCount: vulnerabilities.filter((v: any) => v.severity === 'medium').length,
        lowCount: vulnerabilities.filter((v: any) => v.severity === 'low').length,
        totalRequests: httpRequests.length,
        totalTests: data.totalTests || 0,
        scanDuration: vulnerabilities.reduce((total: number, v: any) => total + (v.duration || 0), 0)
      };

      const scanDate = new Date(data.timestamp || Date.now()).toLocaleDateString('tr-TR');
      const scanTime = new Date(data.timestamp || Date.now()).toLocaleTimeString('tr-TR');

      return this.generateSimpleHtmlReport('Manuel Penetration Test', {
        targetUrl: data.target || 'Unknown Target',
        scanDate,
        scanTime,
        vulnerabilities,
        httpRequests,
        statistics,
        zapStatus: data.zapStatus
      });

    } catch (error) {
      console.error('❌ Manual scan report generation error:', error);
      throw new Error(`Manual scan report generation failed: ${error}`);
    }
  }

  async generateAutomatedScanReport(data: any): Promise<string> {
    try {
      
      const vulnerabilities = data.vulnerabilities?.map((vuln: any, index: number) => ({
        id: vuln.id || index.toString(),
        name: vuln.name || 'Unknown Vulnerability',
        description: vuln.description || 'No description available',
        severity: vuln.severity || 'low',
        confidence: 'Medium',
        solution: vuln.solution || 'No solution provided',
        reference: vuln.reference || '',
        url: vuln.url || data.target || '',
        param: vuln.param || '',
        attack: vuln.attack || '',
        evidence: vuln.evidence || '',
        timestamp: vuln.timestamp || new Date().toISOString()
      })) || [];

      const httpRequests = data.interceptedRequests?.map((req: any) => ({
        method: req.method || 'GET',
        url: req.url || '',
        status: req.status || 0,
        timestamp: req.timestamp || new Date().toISOString(),
        duration: req.duration || 0,
        headers: req.headers || {},
        responseHeaders: req.responseHeaders || {}
      })) || [];

      const statistics = {
        totalVulnerabilities: vulnerabilities.length,
        criticalCount: vulnerabilities.filter((v: any) => v.severity === 'critical').length,
        highCount: vulnerabilities.filter((v: any) => v.severity === 'high' || v.severity === 'High').length,
        mediumCount: vulnerabilities.filter((v: any) => v.severity === 'medium' || v.severity === 'Medium').length,
        lowCount: vulnerabilities.filter((v: any) => v.severity === 'low' || v.severity === 'Low').length,
        totalRequests: httpRequests.length,
        totalTests: data.totalAlerts || 0,
        totalUrlsFound: data.totalUrlsFound || 0,
        scanDuration: data.scanProgress?.duration || 'N/A',
        scanCompleted: data.summary?.scanCompleted || false,
        scanType: data.summary?.scanType || 'Automated Scan'
      };

      const scanDate = new Date(data.timestamp || Date.now()).toLocaleDateString('tr-TR');
      const scanTime = new Date(data.timestamp || Date.now()).toLocaleTimeString('tr-TR');

      return this.generateSimpleHtmlReport('Otomatik Güvenlik Tarama', {
        targetUrl: data.target || 'Unknown Target',
        scanDate,
        scanTime,
        vulnerabilities,
        httpRequests,
        statistics,
        scanConfig: data.scanConfig,
        realTimeAlerts: data.realTimeAlerts || [],
        scanProgress: data.scanProgress
      });

    } catch (error) {
      console.error('❌ Automated scan report generation error:', error);
      throw new Error(`Automated scan report generation failed: ${error}`);
    }
  }

  private mapSeverity(severity: string): string {
    const severityMap: { [key: string]: string } = {
      '3': 'high',
      '2': 'medium', 
      '1': 'low',
      '0': 'info',
      'High': 'high',
      'Medium': 'medium',
      'Low': 'low',
      'Informational': 'info'
    };
    return severityMap[severity] || severity.toLowerCase();
  }

  private calculateStatistics(vulnerabilities: any[], urls: string[]) {
    return {
      totalVulnerabilities: vulnerabilities.length,
      criticalCount: vulnerabilities.filter(v => v.severity === 'critical').length,
      highCount: vulnerabilities.filter(v => v.severity === 'high').length,
      mediumCount: vulnerabilities.filter(v => v.severity === 'medium').length,
      lowCount: vulnerabilities.filter(v => v.severity === 'low').length,
      infoCount: vulnerabilities.filter(v => v.severity === 'info').length,
      totalUrls: urls.length,
      uniqueUrls: [...new Set(urls)].length
    };
  }

  private extractMainTarget(targetUrl: string, sites: any[]): string {
    if (targetUrl && targetUrl !== 'Unknown Target') {
      return targetUrl;
    }
    
    if (sites && sites.length > 0) {
      return sites[0];
    }
    
    return 'Unknown Target';
  }

  private generateSimpleHtmlReport(reportType: string, data: any): string {
    const { targetUrl, scanDate, scanTime, vulnerabilities, httpRequests, statistics } = data;
    
    return `<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SiberZed - ${reportType} Raporu</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; text-align: center; }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header p { font-size: 1.2em; opacity: 0.9; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 5px 15px rgba(0,0,0,0.1); }
        .stat-number { font-size: 2.5em; font-weight: bold; margin-bottom: 5px; }
        .stat-label { color: #666; font-size: 0.9em; }
        .critical { color: #dc3545; }
        .high { color: #fd7e14; }
        .medium { color: #ffc107; }
        .low { color: #28a745; }
        .section { background: white; margin-bottom: 30px; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); overflow: hidden; }
        .section-header { background: #667eea; color: white; padding: 20px; font-size: 1.4em; font-weight: bold; }
        .section-content { padding: 30px; }
        .vulnerability { border-left: 5px solid #ddd; margin-bottom: 20px; padding: 20px; background: #f8f9fa; border-radius: 5px; }
        .vulnerability.critical { border-left-color: #dc3545; }
        .vulnerability.high { border-left-color: #fd7e14; }
        .vulnerability.medium { border-left-color: #ffc107; }
        .vulnerability.low { border-left-color: #28a745; }
        .vulnerability h4 { color: #333; margin-bottom: 10px; font-size: 1.2em; }
        .vulnerability .severity { display: inline-block; padding: 5px 15px; border-radius: 20px; color: white; font-size: 0.9em; font-weight: bold; margin-bottom: 15px; }
        .footer { text-align: center; margin-top: 40px; padding: 20px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ SiberZed ${reportType} Raporu</h1>
            <p>Hedef: ${targetUrl}</p>
            <p>Tarih: ${scanDate} ${scanTime}</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number critical">${statistics.criticalCount || 0}</div>
                <div class="stat-label">Kritik</div>
            </div>
            <div class="stat-card">
                <div class="stat-number high">${statistics.highCount || 0}</div>
                <div class="stat-label">Yüksek</div>
            </div>
            <div class="stat-card">
                <div class="stat-number medium">${statistics.mediumCount || 0}</div>
                <div class="stat-label">Orta</div>
            </div>
            <div class="stat-card">
                <div class="stat-number low">${statistics.lowCount || 0}</div>
                <div class="stat-label">Düşük</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">${statistics.totalRequests || 0}</div>
                <div class="stat-label">HTTP İstekleri</div>
            </div>
        </div>

        ${vulnerabilities && vulnerabilities.length > 0 ? `
        <div class="section">
            <div class="section-header">🔍 Tespit Edilen Güvenlik Açıkları</div>
            <div class="section-content">
                ${vulnerabilities.map((vuln: any) => `
                <div class="vulnerability ${vuln.severity}">
                    <h4>${vuln.name}</h4>
                    <span class="severity ${vuln.severity}">${vuln.severity.toUpperCase()}</span>
                    <p><strong>Açıklama:</strong> ${vuln.description}</p>
                    <p><strong>Hedef:</strong> ${vuln.url}</p>
                    ${vuln.solution ? `<p><strong>Çözüm:</strong> ${vuln.solution}</p>` : ''}
                </div>
                `).join('')}
            </div>
        </div>
        ` : ''}

        <div class="section">
            <div class="section-header">📋 Özet</div>
            <div class="section-content">
                <p>Toplam ${statistics.totalVulnerabilities || 0} güvenlik açığı tespit edildi.</p>
                <p>Toplam ${statistics.totalRequests || 0} HTTP isteği işlendi.</p>
                <p>Rapor oluşturma tarihi: ${new Date().toLocaleString('tr-TR')}</p>
            </div>
        </div>

        <div class="footer">
            <p>Bu rapor <strong>SiberZed Güvenlik Test Platformu</strong> tarafından otomatik olarak oluşturulmuştur.</p>
        </div>
    </div>
</body>
</html>`;
  }

  private generateHtmlTemplate(data: any): string {
    const { targetUrl, scanDate, scanTime, scanType, vulnerabilities, statistics } = data;
    
    return `<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SiberZed - ZAP Güvenlik Raporu</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; border-radius: 10px; margin-bottom: 30px; text-align: center; }
        .header h1 { font-size: 3em; margin-bottom: 15px; }
        .header p { font-size: 1.3em; opacity: 0.9; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 25px; border-radius: 10px; text-align: center; box-shadow: 0 5px 15px rgba(0,0,0,0.1); }
        .stat-number { font-size: 3em; font-weight: bold; margin-bottom: 10px; }
        .stat-label { color: #666; font-size: 1em; }
        .critical { color: #dc3545; }
        .high { color: #fd7e14; }
        .medium { color: #ffc107; }
        .low { color: #28a745; }
        .info { color: #17a2b8; }
        .section { background: white; margin-bottom: 30px; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); overflow: hidden; }
        .section-header { background: #667eea; color: white; padding: 25px; font-size: 1.5em; font-weight: bold; }
        .section-content { padding: 30px; }
        .vulnerability { border-left: 5px solid #ddd; margin-bottom: 25px; padding: 25px; background: #f8f9fa; border-radius: 5px; }
        .vulnerability.critical { border-left-color: #dc3545; }
        .vulnerability.high { border-left-color: #fd7e14; }
        .vulnerability.medium { border-left-color: #ffc107; }
        .vulnerability.low { border-left-color: #28a745; }
        .vulnerability.info { border-left-color: #17a2b8; }
        .vulnerability h4 { color: #333; margin-bottom: 12px; font-size: 1.3em; }
        .vulnerability .severity { display: inline-block; padding: 6px 18px; border-radius: 20px; color: white; font-size: 0.9em; font-weight: bold; margin-bottom: 15px; }
        .footer { text-align: center; margin-top: 40px; padding: 25px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 SiberZed ZAP Güvenlik Raporu</h1>
            <p>Hedef: ${targetUrl}</p>
            <p>Tarih: ${scanDate} ${scanTime}</p>
            <p>Tarama Türü: ${scanType}</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number critical">${statistics.criticalCount}</div>
                <div class="stat-label">Kritik</div>
            </div>
            <div class="stat-card">
                <div class="stat-number high">${statistics.highCount}</div>
                <div class="stat-label">Yüksek</div>
            </div>
            <div class="stat-card">
                <div class="stat-number medium">${statistics.mediumCount}</div>
                <div class="stat-label">Orta</div>
            </div>
            <div class="stat-card">
                <div class="stat-number low">${statistics.lowCount}</div>
                <div class="stat-label">Düşük</div>
            </div>
            <div class="stat-card">
                <div class="stat-number info">${statistics.infoCount}</div>
                <div class="stat-label">Bilgilendirme</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">${statistics.totalUrls}</div>
                <div class="stat-label">URL</div>
            </div>
        </div>

        ${vulnerabilities.length > 0 ? `
        <div class="section">
            <div class="section-header">🔍 Tespit Edilen Güvenlik Açıkları</div>
            <div class="section-content">
                ${vulnerabilities.map((vuln: any) => `
                <div class="vulnerability ${vuln.severity}">
                    <h4>${vuln.name}</h4>
                    <span class="severity ${vuln.severity}">${vuln.severity.toUpperCase()}</span>
                    <div class="details">
                        <p><strong>Açıklama:</strong> ${vuln.description}</p>
                        <p><strong>URL:</strong> ${vuln.url}</p>
                        ${vuln.param ? `<p><strong>Parametre:</strong> ${vuln.param}</p>` : ''}
                        ${vuln.attack ? `<p><strong>Saldırı:</strong> <code>${vuln.attack}</code></p>` : ''}
                        ${vuln.evidence ? `<p><strong>Kanıt:</strong> <pre>${vuln.evidence}</pre></p>` : ''}
                        ${vuln.reference ? `<p><strong>Referans:</strong> ${vuln.reference}</p>` : ''}
                    </div>
                    ${vuln.solution ? `<div class="solution"><strong>💡 Çözüm:</strong> ${vuln.solution}</div>` : ''}
                </div>
                `).join('')}
            </div>
        </div>
        ` : ''}

        <div class="footer">
            <p>Bu rapor <strong>SiberZed Güvenlik Test Platformu</strong> tarafından ${new Date().toLocaleString('tr-TR')} tarihinde oluşturulmuştur.</p>
        </div>
    </div>
</body>
</html>`;
  }
}

export default ZapReportGenerator;
