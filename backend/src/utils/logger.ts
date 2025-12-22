export class Logger {
  private static isDevelopment = process.env.NODE_ENV === 'development';
  private static isProduction = process.env.NODE_ENV === 'production';

  static info(message: string, data?: any) {
    if (this.isDevelopment) {
      console.log(`[INFO] ${new Date().toISOString()} ${message}`, data || '');
    }
  }

  static error(message: string, error?: any) {
    console.error(`[ERROR] ${new Date().toISOString()} ${message}`, error || '');
  }

  static warn(message: string, data?: any) {
    if (this.isDevelopment) {
      console.warn(`[WARN] ${new Date().toISOString()} ${message}`, data || '');
    }
  }

  static debug(message: string, data?: any) {
    if (this.isDevelopment) {
      console.log(`[DEBUG] ${new Date().toISOString()} ${message}`, data || '');
    }
  }

  static auth(message: string, data?: any) {
    console.log(`[AUTH] ${new Date().toISOString()} ${message}`, data || '');
  }

  static security(message: string, data?: any) {
    console.log(`[SECURITY] ${new Date().toISOString()} ${message}`, data || '');
  }
}
