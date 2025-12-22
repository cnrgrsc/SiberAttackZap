import { PrismaClient } from '@prisma/client';
import { EventEmitter } from 'events';

const prisma = new PrismaClient();

interface QueueConfig {
  maxConcurrentScans: number;
  maxScansPerUserPerHour: number;
  maxActiveScansPerUser: number;
  dynamicThreadScaling: boolean;
}

class ScanQueueService extends EventEmitter {
  private config: QueueConfig = {
    maxConcurrentScans: 3, // Aynı anda maksimum 3 tarama
    maxScansPerUserPerHour: 5, // Kullanıcı başına saatte 5 tarama
    maxActiveScansPerUser: 2, // Kullanıcı başına 2 aktif tarama
    dynamicThreadScaling: true, // Otomatik thread ayarlama
  };

  private processingQueue = false;

  constructor() {
    super();
    // Her 10 saniyede bir kuyruğu kontrol et
    setInterval(() => this.processQueue(), 10000);
  }

  /**
   * Kullanıcının tarama yapıp yapamayacağını kontrol et
   */
  async checkUserLimits(userId: string): Promise<{ allowed: boolean; reason?: string }> {
    // 1. Saatlik limit kontrolü
    const oneHourAgo = new Date(Date.now() - 3600000);
    const recentScans = await prisma.scan.count({
      where: {
        createdBy: userId,
        createdAt: { gte: oneHourAgo },
      },
    });

    if (recentScans >= this.config.maxScansPerUserPerHour) {
      return {
        allowed: false,
        reason: `Saatlik tarama limitine ulaştınız (${recentScans}/${this.config.maxScansPerUserPerHour})`,
      };
    }

    // 2. Aktif tarama kontrolü
    const activeScans = await prisma.scan.count({
      where: {
        createdBy: userId,
        status: { in: ['PENDING', 'RUNNING', 'QUEUED'] },
      },
    });

    if (activeScans >= this.config.maxActiveScansPerUser) {
      return {
        allowed: false,
        reason: `Aynı anda maksimum ${this.config.maxActiveScansPerUser} tarama çalıştırabilirsiniz`,
      };
    }

    return { allowed: true };
  }

  /**
   * Taramayı kuyruğa ekle veya direkt başlat
   */
  async addScan(scanId: string, userId: string): Promise<{
    queued: boolean;
    position?: number;
    estimatedStartTime?: Date;
  }> {
    // Önce kullanıcı limitlerini kontrol et
    const limitCheck = await this.checkUserLimits(userId);
    if (!limitCheck.allowed) {
      throw new Error(limitCheck.reason);
    }

    // Aktif tarama sayısını kontrol et
    const activeScans = await this.getActiveScansCount();

    if (activeScans >= this.config.maxConcurrentScans) {
      // Kuyruğa ekle
      const priority = await this.calculatePriority(userId);
      
      await prisma.scanQueue.create({
        data: {
          scanId,
          priority,
        },
      });

      // Taramayı QUEUED durumuna al
      await prisma.scan.update({
        where: { id: scanId },
        data: {
          status: 'QUEUED',
          queuedAt: new Date(),
          queuePriority: priority,
        },
      });

      const position = await this.getQueuePosition(scanId);
      const estimatedStartTime = await this.estimateStartTime(position);

      console.log(`📋 Scan ${scanId} added to queue at position ${position}`);
      
      // Bildirim gönder
      this.emit('scanQueued', { scanId, userId, position, estimatedStartTime });

      return {
        queued: true,
        position,
        estimatedStartTime,
      };
    }

    // Direkt başlatılabilir
    console.log(`✅ Scan ${scanId} can start immediately`);
    return { queued: false };
  }

  /**
   * Aktif tarama sayısını getir
   */
  private async getActiveScansCount(): Promise<number> {
    return await prisma.scan.count({
      where: {
        status: { in: ['RUNNING'] },
      },
    });
  }

  /**
   * Kullanıcı için öncelik hesapla
   * Admin = 1, Security Analyst = 3, User = 5
   */
  private async calculatePriority(userId: string): Promise<number> {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        userRoles: {
          include: {
            role: true,
          },
        },
      },
    });

    if (!user) return 5; // Default priority

    // Admin kontrolü
    const isAdmin = user.userRoles.some(ur => ur.role.name === 'Super Admin' || ur.role.name === 'Admin');
    if (isAdmin) return 1;

    // Security Analyst kontrolü
    const isAnalyst = user.userRoles.some(ur => ur.role.name === 'Security Analyst');
    if (isAnalyst) return 3;

    // Normal user
    return 5;
  }

  /**
   * Taramanın kuyruktaki pozisyonunu getir
   */
  private async getQueuePosition(scanId: string): Promise<number> {
    const queueItems = await prisma.scanQueue.findMany({
      orderBy: [{ priority: 'asc' }, { addedAt: 'asc' }],
    });

    const index = queueItems.findIndex(item => item.scanId === scanId);
    return index + 1;
  }

  /**
   * Tahmini başlama zamanını hesapla
   */
  private async estimateStartTime(position: number): Promise<Date> {
    // Ortalama tarama süresi: 15 dakika
    const avgScanDuration = 15 * 60 * 1000; // 15 dakika in ms
    const estimatedWait = (position - 1) * avgScanDuration / this.config.maxConcurrentScans;
    
    return new Date(Date.now() + estimatedWait);
  }

  /**
   * Kuyruğu işle - bitmiş taramaların yerini yenileriyle doldur
   */
  async processQueue(): Promise<void> {
    if (this.processingQueue) return;
    this.processingQueue = true;

    try {
      const activeScans = await this.getActiveScansCount();
      const availableSlots = this.config.maxConcurrentScans - activeScans;

      if (availableSlots > 0) {
        console.log(`🔄 Processing queue, ${availableSlots} slots available`);

        // Sıradaki taramaları al
        const nextScans = await prisma.scanQueue.findMany({
          take: availableSlots,
          orderBy: [{ priority: 'asc' }, { addedAt: 'asc' }],
          include: {
            scan: true,
          },
        });

        for (const queueItem of nextScans) {
          try {
            // Taramayı PENDING durumuna al (scan service başlatacak)
            await prisma.scan.update({
              where: { id: queueItem.scanId },
              data: {
                status: 'PENDING',
                queuePosition: null,
                queuedAt: null,
              },
            });

            // Kuyruktan çıkar
            await prisma.scanQueue.delete({
              where: { id: queueItem.id },
            });

            console.log(`▶️ Scan ${queueItem.scanId} dequeued and ready to start`);

            // Bildirim gönder
            this.emit('scanDequeued', { scanId: queueItem.scanId });

            // Diğer kuyruktaki taramaların pozisyonlarını güncelle
            await this.updateQueuePositions();
          } catch (error) {
            console.error(`Error processing scan ${queueItem.scanId}:`, error);
          }
        }
      }
    } catch (error) {
      console.error('Error processing queue:', error);
    } finally {
      this.processingQueue = false;
    }
  }

  /**
   * Kuyruk pozisyonlarını güncelle
   */
  private async updateQueuePositions(): Promise<void> {
    const queueItems = await prisma.scanQueue.findMany({
      orderBy: [{ priority: 'asc' }, { addedAt: 'asc' }],
    });

    for (let i = 0; i < queueItems.length; i++) {
      await prisma.scan.update({
        where: { id: queueItems[i].scanId },
        data: { queuePosition: i + 1 },
      });
    }
  }

  /**
   * Taramayı kuyruktan çıkar (manuel iptal)
   */
  async removeScan(scanId: string): Promise<void> {
    await prisma.scanQueue.deleteMany({
      where: { scanId },
    });

    await prisma.scan.update({
      where: { id: scanId },
      data: {
        status: 'CANCELLED',
        queuePosition: null,
        queuedAt: null,
      },
    });

    await this.updateQueuePositions();
    console.log(`🗑️ Scan ${scanId} removed from queue`);
  }

  /**
   * Kuyruk istatistiklerini getir
   */
  async getQueueStats(): Promise<{
    activeScans: number;
    queuedScans: number;
    availableSlots: number;
    queueItems: Array<{
      scanId: string;
      position: number;
      priority: number;
      estimatedStart: Date;
      userName: string;
      targetUrl: string;
    }>;
  }> {
    const activeScans = await this.getActiveScansCount();
    const queuedScans = await prisma.scanQueue.count();

    const queueItems = await prisma.scanQueue.findMany({
      orderBy: [{ priority: 'asc' }, { addedAt: 'asc' }],
      include: {
        scan: {
          include: {
            creator: true,
          },
        },
      },
    });

    const formattedItems = await Promise.all(
      queueItems.map(async (item, index) => ({
        scanId: item.scanId,
        position: index + 1,
        priority: item.priority,
        estimatedStart: await this.estimateStartTime(index + 1),
        userName: item.scan.creator ? `${item.scan.creator.firstName} ${item.scan.creator.lastName}` : 'Unknown',
        targetUrl: item.scan.targetUrl,
      }))
    );

    return {
      activeScans,
      queuedScans,
      availableSlots: Math.max(0, this.config.maxConcurrentScans - activeScans),
      queueItems: formattedItems,
    };
  }

  /**
   * Dinamik thread ayarı hesapla
   */
  async getDynamicThreadCount(): Promise<number> {
    if (!this.config.dynamicThreadScaling) {
      return 10; // Default
    }

    const activeScans = await this.getActiveScansCount();

    if (activeScans <= 1) return 10;
    if (activeScans <= 3) return 5;
    return 2;
  }

  /**
   * Config'i güncelle
   */
  updateConfig(config: Partial<QueueConfig>): void {
    this.config = { ...this.config, ...config };
    console.log('📝 Queue config updated:', this.config);
  }

  /**
   * Config'i getir
   */
  getConfig(): QueueConfig {
    return { ...this.config };
  }
}

// Singleton instance
export const scanQueueService = new ScanQueueService();
export default scanQueueService;
