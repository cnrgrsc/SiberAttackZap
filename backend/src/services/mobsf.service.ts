import axios, { AxiosInstance } from 'axios';
import FormData from 'form-data';
import fs from 'fs';
import { PrismaClient } from '@prisma/client';
import { Server } from 'socket.io';
import { ReportGeneratorService } from './reportGenerator.service';
import { VulnerabilityResponse } from '../types/api.types';

export interface MobSFUploadResponse {
  file_name: string;
  hash: string;
  scan_type: string;
  file_size: number;
}

export interface MobSFScanResult {
  scan_type: string;
  file_name: string;
  hash: string;
  version_name: string;
  version_code: string;
  app_name: string;
  app_type: string;
  size: string;
  md5: string;
  sha1: string;
  sha256: string;
  package_name?: string;
  bundle_id?: string;
  target_sdk?: string;
  min_sdk?: string;
  max_sdk?: string;
  platform?: string;
  findings: MobSFFinding[];
  security_score: number;
  trackers: any[];
  domains: string[];
  urls: string[];
  emails: string[];
  permissions: string[];
  binary_analysis: any;
  certificate_analysis?: any;
}

export interface MobSFFinding {
  id: string;
  title: string;
  type: string;
  description: string;
  file: string;
  severity: 'high' | 'medium' | 'low' | 'info' | 'warning';
  cvss: number;
  cwe: string;
  owasp: string;
  reference: string;
}

export interface MobSFScanSummary {
  file_name: string;
  hash: string;
  scan_type: string;
  timestamp: string;
  analyzer: string;
}

export class MobSFService {
  private client: AxiosInstance;
  private prisma: PrismaClient;
  private io?: Server;

  constructor(prisma: PrismaClient, io?: Server) {
    this.prisma = prisma;
    this.io = io;
    
    this.client = axios.create({
      baseURL: process.env.MOBSF_BASE_URL || 'http://10.5.63.219:5003',
      headers: {
        'X-Mobsf-Api-Key': process.env.MOBSF_API_KEY || '18ec72a9ea33fd33bec9270cb0b70259c12439e969a8c956e8d2003218f3a7b3',
        'Content-Type': 'application/json',
      },
      timeout: 60000 // 60 saniye timeout
    });
  }

  // MobSF bağlantı durumunu kontrol et
  async checkStatus(): Promise<{ connected: boolean; version?: string; error?: string }> {
    const commonApiKeys = [
      '18ec72a9ea33fd33bec9270cb0b70259c12439e969a8c956e8d2003218f3a7b3', // Doğru API Key
      'f659f2a1c01c9e9dc1d9e72fc580d394be657eacbb77dc2c4f95408a81205f15',
      'mobsf_api_key_2023',
      'mobsf_api_key',
      'mobsf',
      'api_key',
      'dd6417a7896f2d7bdc014fc597e909e1f6efb860fccd28c75071b895bd2a9def',
      'mobsf_2023',
      'mobsf_api'
    ];

    try {
      // Önce API key olmadan test et
      const testClient = axios.create({
        baseURL: process.env.MOBSF_BASE_URL || 'http://10.5.63.219:5003',
        timeout: 10000
      });
      
      const response = await testClient.get('/api/v1/scans');
      
      if (response.status === 200) {
        return {
          connected: true,
          version: 'Available (No API Key Required)'
        };
      }
    } catch (error: any) {
      
      // Yaygın API key'leri dene
      for (const apiKey of commonApiKeys) {
        try {
          const testClient = axios.create({
            baseURL: process.env.MOBSF_BASE_URL || 'http://10.5.63.219:5003',
            headers: {
              'X-Mobsf-Api-Key': apiKey,
            },
            timeout: 10000
          });
          
          const response = await testClient.get('/api/v1/scans');
          
          if (response.status === 200) {
            // Çalışan API key'i kaydet
            this.client.defaults.headers['X-Mobsf-Api-Key'] = apiKey;
            return {
              connected: true,
              version: `Available (API Key: ${apiKey})`
            };
          }
        } catch (keyError: any) {
        }
      }
      
      return {
        connected: false,
        error: `All API keys failed. Last error: ${error.message}`
      };
    }
    
    return {
      connected: false,
      error: 'Unknown error'
    };
  }

  // Dosya yükleme
  async uploadFile(filePath: string, fileName: string): Promise<MobSFUploadResponse> {
    try {
      const formData = new FormData();
      formData.append('file', fs.createReadStream(filePath), fileName);

      const apiKey = process.env.MOBSF_API_KEY || '18ec72a9ea33fd33bec9270cb0b70259c12439e969a8c956e8d2003218f3a7b3';
      console.log('🔑 Using API Key:', apiKey.substring(0, 10) + '...');
      
      const response = await this.client.post('/api/v1/upload', formData, {
        headers: {
          ...formData.getHeaders(),
          'X-Mobsf-Api-Key': apiKey, // API key'i açıkça ekle
        },
      });

      this.emitProgress('upload', { status: 'completed', fileName });
      return response.data;
    } catch (error: any) {
      console.error('MobSF upload error:', error);
      this.emitProgress('upload', { status: 'error', error: error.message });
      throw new Error(`Failed to upload file: ${error.message}`);
    }
  }

  // Statik analiz başlatma
  async startScan(hash: string, scanType: string): Promise<any> {
    try {
      this.emitProgress('scan', { status: 'started', hash });
      
      const formData = new FormData();
      formData.append('hash', hash);
      formData.append('scan_type', scanType);
      formData.append('re_scan', '0');
      
      const apiKey = process.env.MOBSF_API_KEY || '18ec72a9ea33fd33bec9270cb0b70259c12439e969a8c956e8d2003218f3a7b3';
      
      const response = await this.client.post('/api/v1/scan', formData, {
        headers: {
          ...formData.getHeaders(),
          'X-Mobsf-Api-Key': apiKey,
        }
      });

      this.emitProgress('scan', { status: 'completed', hash });
      return response.data;
    } catch (error: any) {
      console.error('MobSF scan error:', error);
      this.emitProgress('scan', { status: 'error', error: error.message });
      throw new Error(`Failed to start scan: ${error.message}`);
    }
  }

  // Tarama sonuçlarını al
  async getScanResults(hash: string): Promise<MobSFScanResult> {
    try {
      const formData = new FormData();
      formData.append('hash', hash);
      
      const apiKey = process.env.MOBSF_API_KEY || '18ec72a9ea33fd33bec9270cb0b70259c12439e969a8c956e8d2003218f3a7b3';
      
      const response = await this.client.post('/api/v1/report_json', formData, {
        headers: {
          ...formData.getHeaders(),
          'X-Mobsf-Api-Key': apiKey,
        }
      });
      
      return response.data;
    } catch (error: any) {
      console.error('MobSF get results error:', error);
      throw new Error(`Failed to get scan results: ${error.message}`);
    }
  }

  // PDF rapor indir
  async downloadPDFReport(hash: string): Promise<Buffer> {
    try {
      const formData = new FormData();
      formData.append('hash', hash);
      
      const apiKey = process.env.MOBSF_API_KEY || '18ec72a9ea33fd33bec9270cb0b70259c12439e969a8c956e8d2003218f3a7b3';
      
      const response = await this.client.post('/api/v1/download_pdf', formData, {
        headers: {
          ...formData.getHeaders(),
          'X-Mobsf-Api-Key': apiKey,
        },
        responseType: 'arraybuffer'
      });
      
      return Buffer.from(response.data);
    } catch (error: any) {
      console.error('MobSF PDF download error:', error);
      throw new Error(`Failed to download PDF report: ${error.message}`);
    }
  }

  /**
   * Generate standardized HTML report for mobile scan
   */
  async generateHtmlReport(scanId: string): Promise<string> {
    try {
      // Get scan from database
      const scan = await this.prisma.scan.findUnique({
        where: { id: scanId },
        include: {
          mobileAppScan: true,
          vulnerabilities: true
        }
      });

      if (!scan || !scan.mobileAppScan) {
        throw new Error('Mobile scan not found');
      }

      // Convert vulnerabilities to standard format
      const vulnerabilities: VulnerabilityResponse[] = scan.vulnerabilities.map(v => ({
        id: v.id,
        scanId: v.scanId,
        name: v.name,
        severity: v.severity as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
        confidence: v.confidence || 'Unknown',
        description: v.description || '',
        solution: v.solution || '',
        reference: v.reference || '',
        url: v.url || '',
        param: v.param || '',
        attack: v.attack || '',
        evidence: v.evidence || '',
        cweId: v.cweid || '',
        wascId: v.wascid || '',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      }));

      const scanDuration = scan.completedAt && scan.startedAt ?
        `${Math.round((new Date(scan.completedAt).getTime() - new Date(scan.startedAt).getTime()) / 1000 / 60)} dakika` :
        'Bilinmiyor';

      // Generate standardized report
      return ReportGeneratorService.generateHtmlReport({
        title: scan.name,
        scanType: 'MOBIL_TARAMA',
        targetName: scan.mobileAppScan.appName || scan.mobileAppScan.packageName,
        targetApp: `${scan.mobileAppScan.appName} (${scan.mobileAppScan.platform})`,
        scanDate: scan.startedAt || new Date(),
        scanDuration,
        vulnerabilities,
        additionalInfo: {
          packageName: scan.mobileAppScan.packageName,
          version: scan.mobileAppScan.version,
          platform: scan.mobileAppScan.platform,
          fileSize: scan.mobileAppScan.fileSize,
          securityScore: scan.mobileAppScan.securityScore
        }
      });
    } catch (error: any) {
      console.error('Error generating mobile HTML report:', error);
      throw new Error(`Failed to generate HTML report: ${error.message}`);
    }
  }

  // Son taramaları listele
  async getRecentScans(): Promise<MobSFScanSummary[]> {
    try {
      const response = await this.client.get('/api/v1/scans');
      return response.data;
    } catch (error: any) {
      console.error('MobSF get scans error:', error);
      throw new Error(`Failed to get recent scans: ${error.message}`);
    }
  }

  // Tarama sil
  async deleteScan(hash: string): Promise<void> {
    try {
      const formData = new FormData();
      formData.append('hash', hash);
      
      await this.client.post('/api/v1/delete_scan', formData, {
        headers: {
          ...formData.getHeaders(),
          'X-Mobsf-Api-Key': process.env.MOBSF_API_KEY || 'f659f2a1c01c9e9dc1d9e72fc580d394be657eacbb77dc2c4f95408a81205f15',
        }
      });
    } catch (error: any) {
      console.error('MobSF delete scan error:', error);
      throw new Error(`Failed to delete scan: ${error.message}`);
    }
  }

  // Dinamik analiz - Android uygulamaları listele
  async getAndroidApps(): Promise<any[]> {
    try {
      const response = await this.client.get('/api/v1/dynamic/get_apps');
      return response.data;
    } catch (error: any) {
      console.error('MobSF get Android apps error:', error);
      throw new Error(`Failed to get Android apps: ${error.message}`);
    }
  }

  // Dinamik analiz başlat
  async startDynamicAnalysis(hash: string): Promise<any> {
    try {
      this.emitProgress('dynamic_analysis', { status: 'started', hash });
      
      const formData = new FormData();
      formData.append('hash', hash);
      
      const response = await this.client.post('/api/v1/dynamic/start_analysis', formData, {
        headers: {
          ...formData.getHeaders(),
          'X-Mobsf-Api-Key': process.env.MOBSF_API_KEY || 'f659f2a1c01c9e9dc1d9e72fc580d394be657eacbb77dc2c4f95408a81205f15',
        }
      });
      
      this.emitProgress('dynamic_analysis', { status: 'completed', hash });
      return response.data;
    } catch (error: any) {
      console.error('MobSF dynamic analysis error:', error);
      this.emitProgress('dynamic_analysis', { status: 'error', error: error.message });
      throw new Error(`Failed to start dynamic analysis: ${error.message}`);
    }
  }

  // Dinamik analiz durdur
  async stopDynamicAnalysis(hash: string): Promise<any> {
    try {
      const formData = new FormData();
      formData.append('hash', hash);
      
      const response = await this.client.post('/api/v1/dynamic/stop_analysis', formData, {
        headers: {
          ...formData.getHeaders(),
          'X-Mobsf-Api-Key': process.env.MOBSF_API_KEY || 'f659f2a1c01c9e9dc1d9e72fc580d394be657eacbb77dc2c4f95408a81205f15',
        }
      });
      return response.data;
    } catch (error: any) {
      console.error('MobSF stop dynamic analysis error:', error);
      throw new Error(`Failed to stop dynamic analysis: ${error.message}`);
    }
  }

  // Tam mobil uygulama tarama workflow'u
  async runCompleteWorkflow(filePath: string, fileName: string, scanId?: string): Promise<MobSFScanResult> {
    try {
      let dbScanId = scanId;
      
      if (!dbScanId) {
        // Veritabanında yeni tarama kaydı oluştur
        const scan = await this.prisma.scan.create({
          data: {
            name: `Mobile Scan - ${fileName}`,
            targetUrl: fileName,
            scanType: 'MOBILE',
            status: 'RUNNING',
            startedAt: new Date(),
          }
        });
        dbScanId = scan.id;
      }

      this.emitProgress('workflow', { 
        status: 'started', 
        stage: 'upload',
        scanId: dbScanId,
        message: 'Dosya yükleniyor...' 
      });

      // 1. Dosya yükle
      const uploadResult = await this.uploadFile(filePath, fileName);
      
      this.emitProgress('workflow', { 
        status: 'progress', 
        stage: 'scan',
        scanId: dbScanId,
        message: 'Statik analiz başlatılıyor...' 
      });

      // 2. Statik analiz başlat
      await this.startScan(uploadResult.hash, uploadResult.scan_type);
      
      this.emitProgress('workflow', { 
        status: 'progress', 
        stage: 'results',
        scanId: dbScanId,
        message: 'Sonuçlar alınıyor...' 
      });

      // 3. Sonuçları al
      const scanResults = await this.getScanResults(uploadResult.hash);

      // 4. Sonuçları veritabanına kaydet
      await this.saveScanResults(dbScanId, scanResults, uploadResult.hash);

      this.emitProgress('workflow', { 
        status: 'completed', 
        stage: 'finished',
        scanId: dbScanId,
        message: 'Tarama tamamlandı!' 
      });

      return scanResults;
    } catch (error: any) {
      console.error('MobSF complete workflow error:', error);
      
      if (scanId) {
        await this.prisma.scan.update({
          where: { id: scanId },
          data: { status: 'FAILED', completedAt: new Date() }
        });
      }

      this.emitProgress('workflow', { 
        status: 'error', 
        error: error.message 
      });
      
      throw error;
    }
  }

  // Tarama sonuçlarını veritabanına kaydet
  private async saveScanResults(scanId: string, results: MobSFScanResult, hash: string): Promise<void> {
    try {
      // Tarama kaydını güncelle
      await this.prisma.scan.update({
        where: { id: scanId },
        data: {
          status: 'COMPLETED',
          completedAt: new Date(),
        }
      });

      // Güvenlik açıklarını kaydet
      for (const finding of results.findings || []) {
        await this.prisma.vulnerability.create({
          data: {
            scanId,
            name: finding.title,
            severity: this.mapSeverity(finding.severity),
            description: finding.description,
            solution: finding.reference || '',
            cweid: finding.cwe || '',
            evidence: JSON.stringify(finding),
          }
        });
      }

      // Mobil uygulama detaylarını kaydet
      await this.prisma.mobileAppScan.create({
        data: {
          scanId,
          hash,
          appName: results.app_name || '',
          packageName: results.package_name || results.bundle_id || '',
          version: results.version_name || results.version_code || '',
          platform: results.scan_type === 'apk' || results.scan_type === 'aab' ? 'ANDROID' : 'IOS',
          fileSize: parseInt(results.size || '0') || 0,
          securityScore: results.security_score || 0,
          permissions: JSON.stringify(results.permissions || []),
          trackers: JSON.stringify(results.trackers || []),
          domains: JSON.stringify(results.domains || []),
          urls: JSON.stringify(results.urls || []),
          emails: JSON.stringify(results.emails || []),
          mobsfVersion: 'MobSF Latest',
        }
      });

    } catch (error: any) {
      console.error('Error saving MobSF scan results:', error);
      throw error;
    }
  }

  // Socket.IO ile ilerleme durumu gönder
  private emitProgress(event: string, data: any): void {
    if (this.io) {
      this.io.emit(`mobsf_${event}`, data);
    }
  }

  // Severity mapping
  private mapSeverity(severity: string): string {
    switch (severity.toLowerCase()) {
      case 'high': return 'HIGH';
      case 'medium': return 'MEDIUM';
      case 'low': return 'LOW';
      case 'info': return 'INFO';
      case 'warning': return 'LOW';
      default: return 'MEDIUM';
    }
  }

  // MobSF durumunu kontrol et
  async getStatus(): Promise<{ isRunning: boolean; version?: string }> {
    try {
      const response = await this.client.get('/api/v1/scans', { timeout: 5000 });
      return { isRunning: true, version: 'MobSF API' };
    } catch (error) {
      return { isRunning: false };
    }
  }
}

export default MobSFService;
