import crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '';

if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length !== 64) {
    console.warn('⚠️  ENCRYPTION_KEY not set or invalid. Please set a 64-character hex key in .env');
}

const KEY = Buffer.from(ENCRYPTION_KEY, 'hex');

/**
 * Encrypt sensitive text using AES-256-GCM
 * @param text - Plain text to encrypt
 * @returns Encrypted string in format: iv:authTag:encrypted
 */
export function encrypt(text: string): string {
    try {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv);

        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        const authTag = cipher.getAuthTag();

        // Format: iv:authTag:encrypted
        return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
    } catch (error) {
        console.error('❌ Encryption failed:', error);
        throw new Error('Failed to encrypt data');
    }
}

/**
 * Decrypt AES-256-GCM encrypted text
 * @param encrypted - Encrypted string in format: iv:authTag:encrypted
 * @returns Decrypted plain text
 */
export function decrypt(encrypted: string): string {
    try {
        const parts = encrypted.split(':');

        if (parts.length !== 3) {
            throw new Error('Invalid encrypted data format');
        }

        const iv = Buffer.from(parts[0], 'hex');
        const authTag = Buffer.from(parts[1], 'hex');
        const encryptedText = parts[2];

        const decipher = crypto.createDecipheriv(ALGORITHM, KEY, iv);
        decipher.setAuthTag(authTag);

        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    } catch (error) {
        console.error('❌ Decryption failed:', error);
        throw new Error('Failed to decrypt data');
    }
}

/**
 * Mask a token for display purposes
 * @param token - Token to mask
 * @param visibleChars - Number of characters to show at the end
 * @returns Masked token (e.g., "●●●●●●●●●●abc123")
 */
export function maskToken(token: string, visibleChars: number = 6): string {
    if (!token || token.length <= visibleChars) {
        return '●●●●●●●●●●';
    }

    const maskedPart = '●'.repeat(Math.max(10, token.length - visibleChars));
    const visiblePart = token.slice(-visibleChars);

    return `${maskedPart}${visiblePart}`;
}

/**
 * Generate a random 256-bit encryption key (for initial setup)
 * @returns 64-character hex string
 */
export function generateEncryptionKey(): string {
    return crypto.randomBytes(32).toString('hex');
}
