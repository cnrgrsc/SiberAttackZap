-- AlterTable
ALTER TABLE "scans" ADD COLUMN     "aggressiveness" TEXT DEFAULT 'MEDIUM',
ADD COLUMN     "environment" TEXT DEFAULT 'TEST',
ADD COLUMN     "reportSettings" JSONB,
ADD COLUMN     "safeMode" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "scanConfig" JSONB;
