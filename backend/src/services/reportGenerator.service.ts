import { VulnerabilityResponse } from '../types/api.types';

interface ReportData {
  title: string;
  scanType: 'WEB_TARAMASI' | 'MOBIL_TARAMA' | 'API_TARAMASI';
  targetName: string;
  targetUrl?: string;
  targetApp?: string;
  scanDate: Date;
  scanDuration?: string;
  vulnerabilities: VulnerabilityResponse[];
  additionalInfo?: {
    [key: string]: any;
  };
}

export class ReportGeneratorService {
  
  /**
   * Generate standardized filename for security scan reports
   */
  static generateFilename(scanType: string, targetName: string): string {
    const now = new Date();
    const day = String(now.getDate()).padStart(2, '0');
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const year = now.getFullYear();
    const hour = String(now.getHours()).padStart(2, '0');
    const minute = String(now.getMinutes()).padStart(2, '0');
    
    const dateStr = `${day}_${month}_${year}_${hour}_${minute}`;
    
    // Clean target name - remove special characters, limit length
    const cleanTarget = targetName
      .replace(/[^a-zA-Z0-9]/g, '_')
      .substring(0, 30);
    
    const scanTypeMap: { [key: string]: string } = {
      'WEB': 'WebTaramasi',
      'AUTOMATED': 'WebTaramasi',
      'MOBILE': 'MobilTarama',
      'API': 'ApiTaramasi',
      'MANUAL': 'ManuelTarama'
    };
    
    const typeStr = scanTypeMap[scanType.toUpperCase()] || 'Tarama';
    
    return `IBB_GuvenlikTaramasi_${dateStr}_${typeStr}_${cleanTarget}.html`;
  }

  /**
   * Generate standardized HTML report with new format
   */
  static generateHtmlReport(data: ReportData): string {
    const severityColors = {
      'CRITICAL': '#b71c1c',
      'HIGH': '#d32f2f',
      'MEDIUM': '#f57c00',
      'LOW': '#388e3c',
      'INFO': '#1976d2'
    };

    const severityStats = {
      CRITICAL: data.vulnerabilities.filter(v => v.severity === 'CRITICAL').length,
      HIGH: data.vulnerabilities.filter(v => v.severity === 'HIGH').length,
      MEDIUM: data.vulnerabilities.filter(v => v.severity === 'MEDIUM').length,
      LOW: data.vulnerabilities.filter(v => v.severity === 'LOW').length,
      INFO: data.vulnerabilities.filter(v => v.severity === 'INFO').length
    };

    const reportDate = data.scanDate.toLocaleString('tr-TR', {
      day: 'numeric',
      month: 'long',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });

    const scanTypeIcon = {
      'WEB_TARAMASI': '🌐',
      'MOBIL_TARAMA': '📱',
      'API_TARAMASI': '🔌'
    }[data.scanType] || '🛡️';

    const scanTypeLabel = {
      'WEB_TARAMASI': 'Web Uygulaması Taraması',
      'MOBIL_TARAMA': 'Mobil Uygulama Taraması',
      'API_TARAMASI': 'API Güvenlik Taraması'
    }[data.scanType] || 'Güvenlik Taraması';
    
    const securityScore = this.calculateSecurityScore(data.vulnerabilities);
    const scoreColor = this.getSecurityScoreColor(data.vulnerabilities);
    const sortedVulns = this.sortVulnerabilitiesBySeverity(data.vulnerabilities);

    return `
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>İBB Güvenlik Tarama Raporu - ${data.targetName}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', 'Arial', sans-serif;
            background: #f5f7fa;
            color: #333;
            line-height: 1.6;
        }
        .container { 
            max-width: 1400px; 
            margin: 0 auto; 
            background: white; 
            box-shadow: 0 0 30px rgba(0,0,0,0.1);
        }
        
        /* HEADER */
        .header { 
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 50%, #7e8ba3 100%);
            color: white; 
            padding: 40px 50px;
            position: relative;
            overflow: hidden;
        }
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg width="100" height="100" xmlns="http://www.w3.org/2000/svg"><defs><pattern id="grid" width="100" height="100" patternUnits="userSpaceOnUse"><path d="M 100 0 L 0 0 0 100" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="1"/></pattern></defs><rect width="100%" height="100%" fill="url(%23grid)"/></svg>');
            opacity: 0.3;
        }
        .header-content { position: relative; z-index: 1; }
        .header h1 { 
            font-size: 2.8em; 
            margin-bottom: 15px;
            font-weight: 600;
            letter-spacing: -0.5px;
        }
        .header .subtitle { 
            font-size: 1.3em; 
            opacity: 0.95;
            margin-bottom: 10px;
        }
        .header .meta { 
            opacity: 0.85; 
            font-size: 0.95em;
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid rgba(255,255,255,0.2);
        }
        
        /* SUMMARY SECTION */
        .summary { 
            padding: 50px;
            background: linear-gradient(to bottom, #ffffff 0%, #f8f9fa 100%);
        }
        .summary h2 { 
            font-size: 2em; 
            color: #1e3c72;
            margin-bottom: 30px;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .summary-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
            gap: 25px; 
            margin: 30px 0;
        }
        .summary-card { 
            background: white;
            padding: 30px;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            border-left: 5px solid #2196F3;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .summary-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
        }
        .summary-card h3 { 
            font-size: 0.95em;
            color: #666;
            margin-bottom: 15px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .summary-card .number { 
            font-size: 2.5em; 
            font-weight: bold; 
            color: #2196F3;
            line-height: 1;
        }
        .summary-card .label {
            font-size: 0.85em;
            color: #999;
            margin-top: 8px;
        }
        
        /* SEVERITY CHART */
        .severity-section {
            margin-top: 50px;
        }
        .severity-section h3 {
            font-size: 1.5em;
            color: #1e3c72;
            margin-bottom: 25px;
        }
        .severity-chart { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); 
            gap: 20px;
        }
        .severity-item { 
            text-align: center; 
            padding: 25px 20px;
            border-radius: 12px;
            color: white;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
            transition: transform 0.2s;
        }
        .severity-item:hover {
            transform: scale(1.05);
        }
        .severity-item .count {
            font-size: 3em;
            font-weight: bold;
            line-height: 1;
            margin-bottom: 10px;
        }
        .severity-item .label {
            font-size: 1.1em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        /* VULNERABILITIES SECTION */
        .vulnerabilities { 
            padding: 50px;
            background: #f8f9fa;
        }
        .vulnerabilities h2 {
            font-size: 2em;
            color: #1e3c72;
            margin-bottom: 30px;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .vuln-item { 
            margin: 25px 0;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            background: white;
            transition: box-shadow 0.2s;
        }
        .vuln-item:hover {
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
        }
        .vuln-header { 
            padding: 25px 30px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            user-select: none;
        }
        .vuln-header-left {
            display: flex;
            align-items: center;
            gap: 15px;
            flex: 1;
        }
        .vuln-details { 
            padding: 0;
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease, padding 0.3s ease;
            background: #f9fafb;
        }
        .vuln-details.show { 
            max-height: 2000px;
            padding: 30px;
        }
        .severity-badge { 
            padding: 8px 16px;
            border-radius: 25px;
            color: white;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            min-width: 90px;
            text-align: center;
        }
        .vuln-name {
            font-size: 1.1em;
            font-weight: 600;
            color: #333;
        }
        .toggle-btn { 
            background: none;
            border: none;
            font-size: 1.5em;
            cursor: pointer;
            color: #666;
            transition: transform 0.2s;
            padding: 5px 10px;
        }
        .vuln-details.show + .vuln-header .toggle-btn {
            transform: rotate(180deg);
        }
        .info-grid { 
            display: grid;
            gap: 25px;
        }
        .info-item { 
            margin: 15px 0;
            padding: 20px;
            background: white;
            border-radius: 8px;
            border-left: 4px solid #2196F3;
        }
        .info-item strong { 
            color: #1e3c72;
            font-size: 1.05em;
            display: block;
            margin-bottom: 10px;
        }
        .info-item p {
            color: #555;
            line-height: 1.7;
        }
        .info-item code {
            background: #f0f2f5;
            padding: 15px;
            border-radius: 6px;
            display: block;
            margin-top: 10px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            border: 1px solid #ddd;
        }
        .no-vulns { 
            text-align: center;
            padding: 80px 40px;
            background: linear-gradient(135deg, #e8f5e9 0%, #c8e6c9 100%);
            border-radius: 12px;
            margin: 20px 0;
        }
        .no-vulns h3 {
            font-size: 2em;
            color: #2e7d32;
            margin-bottom: 15px;
        }
        .no-vulns p {
            font-size: 1.2em;
            color: #558b2f;
        }
        
        /* FOOTER */
        .footer { 
            background: #1e3c72;
            color: white;
            padding: 40px 50px;
            text-align: center;
        }
        .footer p { 
            margin: 8px 0;
            opacity: 0.9;
        }
        .footer .copyright {
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid rgba(255,255,255,0.2);
            font-size: 0.9em;
        }
        
        /* PRINT STYLES */
        @media print {
            body { background: white; }
            .container { box-shadow: none; }
            .vuln-details { max-height: none !important; display: block !important; }
            .toggle-btn { display: none; }
            .vuln-header { cursor: default; }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- HEADER -->
        <div class="header">
            <div class="header-content">
                <h1>${scanTypeIcon} İBB Güvenlik Tarama Raporu</h1>
                <div class="subtitle">${scanTypeLabel}</div>
                <div class="subtitle" style="font-size: 1.1em; margin-top: 10px;">
                    <strong>${data.targetName}</strong>
                </div>
                <div class="meta">
                    <div><strong>Rapor Tarihi:</strong> ${reportDate}</div>
                    ${data.targetUrl ? `<div><strong>Hedef URL:</strong> ${data.targetUrl}</div>` : ''}
                    ${data.targetApp ? `<div><strong>Uygulama:</strong> ${data.targetApp}</div>` : ''}
                    ${data.scanDuration ? `<div><strong>Tarama Süresi:</strong> ${data.scanDuration}</div>` : ''}
                </div>
            </div>
        </div>

        <!-- SUMMARY -->
        <div class="summary">
            <h2>📊 Tarama Özeti</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Tarama Türü</h3>
                    <div class="number">${scanTypeIcon}</div>
                    <div class="label">${scanTypeLabel}</div>
                </div>
                <div class="summary-card" style="border-left-color: #f44336;">
                    <h3>Toplam Zafiyet</h3>
                    <div class="number" style="color: #f44336;">${data.vulnerabilities.length}</div>
                    <div class="label">Tespit Edildi</div>
                </div>
                <div class="summary-card" style="border-left-color: #d32f2f;">
                    <h3>Kritik & Yüksek Risk</h3>
                    <div class="number" style="color: #d32f2f;">${severityStats.CRITICAL + severityStats.HIGH}</div>
                    <div class="label">Öncelikli Düzeltme</div>
                </div>
                <div class="summary-card" style="border-left-color: #4caf50;">
                    <h3>Güvenlik Skoru</h3>
                    <div class="number" style="color: ${scoreColor};">
                        ${securityScore}
                    </div>
                    <div class="label">/ 100</div>
                </div>
            </div>

            <!-- SEVERITY DISTRIBUTION -->
            <div class="severity-section">
                <h3>🎯 Zafiyet Dağılımı (Önem Derecesine Göre)</h3>
                <div class="severity-chart">
                    <div class="severity-item" style="background: linear-gradient(135deg, ${severityColors.CRITICAL} 0%, #8b0000 100%);">
                        <div class="count">${severityStats.CRITICAL}</div>
                        <div class="label">KRİTİK</div>
                    </div>
                    <div class="severity-item" style="background: linear-gradient(135deg, ${severityColors.HIGH} 0%, #b71c1c 100%);">
                        <div class="count">${severityStats.HIGH}</div>
                        <div class="label">YÜKSEK</div>
                    </div>
                    <div class="severity-item" style="background: linear-gradient(135deg, ${severityColors.MEDIUM} 0%, #e65100 100%);">
                        <div class="count">${severityStats.MEDIUM}</div>
                        <div class="label">ORTA</div>
                    </div>
                    <div class="severity-item" style="background: linear-gradient(135deg, ${severityColors.LOW} 0%, #2e7d32 100%);">
                        <div class="count">${severityStats.LOW}</div>
                        <div class="label">DÜŞÜK</div>
                    </div>
                    <div class="severity-item" style="background: linear-gradient(135deg, ${severityColors.INFO} 0%, #1565c0 100%);">
                        <div class="count">${severityStats.INFO}</div>
                        <div class="label">BİLGİ</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- API DEEP DIVE RESULTS -->
        ${data.additionalInfo?.apiSecurity ? `
        <div class="api-deep-dive-section" style="margin-bottom: 40px; padding: 30px; background: linear-gradient(135deg, #e8f5e9 0%, #f1f8e9 100%); border-radius: 15px; border: 2px solid #4caf50; box-shadow: 0 5px 15px rgba(76, 175, 80, 0.2);">
            <h2 style="color: #2e7d32; margin-bottom: 25px; display: flex; align-items: center; gap: 10px;">
                🔌 API Deep Dive Analiz Sonuçları
            </h2>
            
            <!-- API Summary Cards -->
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px;">
                <div style="background: white; padding: 20px; border-radius: 10px; border-left: 4px solid #4caf50; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                    <h4 style="color: #2e7d32; margin: 0 0 10px 0; font-size: 0.9em;">Güvenlik Skoru</h4>
                    <div style="font-size: 2em; font-weight: bold; color: ${this.getApiScoreColor(data.additionalInfo.apiSecurity.securityScore)};">
                        ${data.additionalInfo.apiSecurity.securityScore || 'N/A'}/100
                    </div>
                </div>
                
                <div style="background: white; padding: 20px; border-radius: 10px; border-left: 4px solid #ff5722; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                    <h4 style="color: #d32f2f; margin: 0 0 10px 0; font-size: 0.9em;">API Zafiyetleri</h4>
                    <div style="font-size: 2em; font-weight: bold; color: #d32f2f;">
                        ${data.additionalInfo.apiSecurity.vulnerabilities?.length || 0}
                    </div>
                </div>
                
                <div style="background: white; padding: 20px; border-radius: 10px; border-left: 4px solid #2196f3; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                    <h4 style="color: #1976d2; margin: 0 0 10px 0; font-size: 0.9em;">HTTP Metodları</h4>
                    <div style="font-size: 2em; font-weight: bold; color: #1976d2;">
                        ${Object.keys(data.additionalInfo.apiSecurity.endpointsByMethod || {}).length}
                    </div>
                </div>
                
                <div style="background: white; padding: 20px; border-radius: 10px; border-left: 4px solid #9c27b0; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                    <h4 style="color: #7b1fa2; margin: 0 0 10px 0; font-size: 0.9em;">Parametre Tipleri</h4>
                    <div style="font-size: 2em; font-weight: bold; color: #7b1fa2;">
                        ${Object.keys(data.additionalInfo.apiSecurity.parameterTypes || {}).length}
                    </div>
                </div>
            </div>
            
            <!-- Top Endpoints -->
            ${data.additionalInfo.apiSecurity.endpoints && data.additionalInfo.apiSecurity.endpoints.length > 0 ? `
            <div style="background: white; padding: 25px; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                <h3 style="color: #2e7d32; margin: 0 0 20px 0;">📍 En Çok Kullanılan API Endpoint'leri (İlk 10)</h3>
                <div style="display: flex; flex-direction: column; gap: 15px;">
                    ${data.additionalInfo.apiSecurity.endpoints.slice(0, 10).map((endpoint: any, idx: number) => `
                        <div style="display: flex; align-items: center; gap: 15px; padding: 15px; border: 1px solid #e0e0e0; border-radius: 8px; background: ${idx % 2 === 0 ? '#fafafa' : 'white'};">
                            <span style="font-weight: bold; color: #666; min-width: 30px;">#${idx + 1}</span>
                            <span style="padding: 4px 12px; border-radius: 5px; font-weight: bold; font-size: 0.85em; min-width: 70px; text-align: center; color: white; background: ${this.getMethodColor(endpoint.method)};">
                                ${endpoint.method}
                            </span>
                            <span style="flex: 1; font-family: 'Courier New', monospace; font-size: 0.9em; color: #333; word-break: break-all;">
                                ${this.escapeHtml(endpoint.path || endpoint.url || 'N/A')}
                            </span>
                            <span style="padding: 4px 10px; border-radius: 5px; background: #e3f2fd; color: #1976d2; font-size: 0.85em; min-width: 60px; text-align: center;">
                                ${endpoint.parameters?.length || 0} param
                            </span>
                        </div>
                    `).join('')}
                </div>
            </div>
            ` : ''}
            
            <!-- HTTP Methods Distribution -->
            ${data.additionalInfo.apiSecurity.endpointsByMethod && Object.keys(data.additionalInfo.apiSecurity.endpointsByMethod).length > 0 ? `
            <div style="background: white; padding: 25px; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); margin-top: 20px;">
                <h3 style="color: #2e7d32; margin: 0 0 20px 0;">📊 HTTP Metod Dağılımı</h3>
                <div style="display: flex; flex-wrap: wrap; gap: 15px;">
                    ${Object.entries(data.additionalInfo.apiSecurity.endpointsByMethod).map(([method, endpoints]: [string, any]) => `
                        <div style="padding: 15px 25px; border-radius: 8px; background: ${this.getMethodColor(method)}; color: white; box-shadow: 0 2px 5px rgba(0,0,0,0.2);">
                            <div style="font-weight: bold; font-size: 0.9em;">${method}</div>
                            <div style="font-size: 1.8em; font-weight: bold; margin-top: 5px;">${endpoints.length}</div>
                        </div>
                    `).join('')}
                </div>
            </div>
            ` : ''}
        </div>
        ` : ''}

        <!-- VULNERABILITIES -->
        <div class="vulnerabilities">
            <h2>🔍 Tespit Edilen Zafiyetler</h2>
            ${data.vulnerabilities.length === 0 ?
                `<div class="no-vulns">
                    <h3>✅ Tebrikler!</h3>
                    <p>Bu taramada herhangi bir güvenlik zafiyeti tespit edilmedi.</p>
                    <p style="margin-top: 15px; font-size: 1em;">Sistemleriniz temel güvenlik kontrollerinden başarıyla geçti.</p>
                </div>` :
                sortedVulns.map((vuln, index) => `
                <div class="vuln-item">
                    <div class="vuln-header" onclick="toggleDetails(${index})">
                        <div class="vuln-header-left">
                            <span class="severity-badge" style="background: linear-gradient(135deg, ${severityColors[vuln.severity as keyof typeof severityColors]} 0%, ${this.getDarkerColor(severityColors[vuln.severity as keyof typeof severityColors])} 100%);">
                                ${vuln.severity}
                            </span>
                            <span class="vuln-name">${this.escapeHtml(vuln.name)}</span>
                        </div>
                        <button class="toggle-btn" id="btn-${index}" aria-label="Toggle details">▼</button>
                    </div>
                    <div class="vuln-details" id="details-${index}">
                        <div class="info-grid">
                            ${vuln.url ? `
                            <div class="info-item">
                                <strong>🌐 Etkilenen URL</strong>
                                <p style="word-break: break-all;">${this.escapeHtml(vuln.url)}</p>
                            </div>
                            ` : ''}
                            
                            ${vuln.param ? `
                            <div class="info-item">
                                <strong>⚙️ Parametre</strong>
                                <p><code>${this.escapeHtml(vuln.param)}</code></p>
                            </div>
                            ` : ''}
                            
                            ${vuln.confidence ? `
                            <div class="info-item">
                                <strong>📊 Güven Seviyesi</strong>
                                <p>${vuln.confidence}</p>
                            </div>
                            ` : ''}
                            
                            ${vuln.description ? `
                            <div class="info-item">
                                <strong>📝 Açıklama</strong>
                                <p>${this.escapeHtml(vuln.description)}</p>
                            </div>
                            ` : ''}
                            
                            ${vuln.solution ? `
                            <div class="info-item" style="border-left-color: #4caf50;">
                                <strong>✅ Çözüm Önerisi</strong>
                                <p>${this.escapeHtml(vuln.solution)}</p>
                            </div>
                            ` : ''}
                            
                            ${vuln.evidence ? `
                            <div class="info-item" style="border-left-color: #ff9800;">
                                <strong>🔎 Kanıt</strong>
                                <code>${this.escapeHtml(vuln.evidence)}</code>
                            </div>
                            ` : ''}
                            
                            ${vuln.reference ? `
                            <div class="info-item" style="border-left-color: #9c27b0;">
                                <strong>📚 Referanslar</strong>
                                <p>${this.escapeHtml(vuln.reference)}</p>
                            </div>
                            ` : ''}
                        </div>
                    </div>
                </div>
                `).join('')
            }
        </div>

        <!-- FOOTER -->
        <div class="footer">
            <p><strong>İstanbul Büyükşehir Belediyesi</strong></p>
            <p>Bilgi İşlem Daire Başkanlığı - Siber Güvenlik Birimi</p>
            <p>Güvenlik Test Platformu v2.0</p>
            <div class="copyright">
                <p>© 2025 İstanbul Büyükşehir Belediyesi. Tüm hakları saklıdır.</p>
                <p style="font-size: 0.85em; opacity: 0.8; margin-top: 10px;">
                    Bu rapor ${reportDate} tarihinde otomatik olarak oluşturulmuştur.
                </p>
            </div>
        </div>
    </div>

    <script>
        function toggleDetails(index) {
            const details = document.getElementById('details-' + index);
            const btn = document.getElementById('btn-' + index);
            
            if (details.classList.contains('show')) {
                details.classList.remove('show');
                btn.textContent = '▼';
                btn.setAttribute('aria-expanded', 'false');
            } else {
                details.classList.add('show');
                btn.textContent = '▲';
                btn.setAttribute('aria-expanded', 'true');
            }
        }
        
        // Print functionality
        function printReport() {
            window.print();
        }
        
        // Expand all for printing
        window.addEventListener('beforeprint', function() {
            document.querySelectorAll('.vuln-details').forEach(el => {
                el.classList.add('show');
            });
        });
    </script>
</body>
</html>`;
  }

  /**
   * Sort vulnerabilities by severity (CRITICAL > HIGH > MEDIUM > LOW > INFO)
   */
  private static sortVulnerabilitiesBySeverity(vulnerabilities: VulnerabilityResponse[]): VulnerabilityResponse[] {
    const severityOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4 };
    return [...vulnerabilities].sort((a, b) => {
      const orderA = severityOrder[a.severity as keyof typeof severityOrder] ?? 999;
      const orderB = severityOrder[b.severity as keyof typeof severityOrder] ?? 999;
      return orderA - orderB;
    });
  }

  /**
   * Calculate security score (0-100) based on vulnerabilities
   */
  private static calculateSecurityScore(vulnerabilities: VulnerabilityResponse[]): number {
    let score = 100;
    
    vulnerabilities.forEach(vuln => {
      switch (vuln.severity) {
        case 'CRITICAL': score -= 15; break;
        case 'HIGH': score -= 10; break;
        case 'MEDIUM': score -= 5; break;
        case 'LOW': score -= 2; break;
        case 'INFO': score -= 0; break;
      }
    });
    
    return Math.max(0, score);
  }

  /**
   * Get color based on security score
   */
  private static getSecurityScoreColor(vulnerabilities: VulnerabilityResponse[]): string {
    const score = this.calculateSecurityScore(vulnerabilities);
    
    if (score >= 80) return '#4caf50'; // Green
    if (score >= 60) return '#ff9800'; // Orange
    if (score >= 40) return '#f57c00'; // Dark Orange
    return '#d32f2f'; // Red
  }

  /**
   * Get darker shade of a color
   */
  private static getDarkerColor(color: string): string {
    const colorMap: { [key: string]: string } = {
      '#b71c1c': '#7f0000',
      '#d32f2f': '#b71c1c',
      '#f57c00': '#e65100',
      '#388e3c': '#2e7d32',
      '#1976d2': '#1565c0'
    };
    return colorMap[color] || color;
  }

  /**
   * Escape HTML special characters
   */
  private static escapeHtml(unsafe: string): string {
    if (!unsafe) return '';
    return unsafe
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  /**
   * Get color for API security score
   */
  private static getApiScoreColor(score: number): string {
    if (!score) return '#999';
    if (score >= 80) return '#4caf50'; // Green
    if (score >= 60) return '#ff9800'; // Orange
    if (score >= 40) return '#f57c00'; // Dark Orange
    return '#d32f2f'; // Red
  }

  /**
   * Get color for HTTP method
   */
  private static getMethodColor(method: string): string {
    const methodColors: { [key: string]: string } = {
      'GET': '#2196f3',      // Blue
      'POST': '#4caf50',     // Green
      'PUT': '#ff9800',      // Orange
      'DELETE': '#f44336',   // Red
      'PATCH': '#9c27b0',    // Purple
      'HEAD': '#00bcd4',     // Cyan
      'OPTIONS': '#607d8b'   // Blue Grey
    };
    return methodColors[method.toUpperCase()] || '#9e9e9e'; // Grey for unknown
  }
}
