-- AlterTable
ALTER TABLE "vulnerabilities" ADD COLUMN     "affectedUrl" TEXT,
ADD COLUMN     "cvssScore" DOUBLE PRECISION,
ADD COLUMN     "cweId" TEXT,
ADD COLUMN     "cweid" TEXT,
ADD COLUMN     "mobsfType" TEXT,
ADD COLUMN     "otherInfo" TEXT,
ADD COLUMN     "owaspCategory" TEXT,
ADD COLUMN     "wascid" TEXT;

-- CreateTable
CREATE TABLE "access_requests" (
    "id" TEXT NOT NULL,
    "firstName" TEXT NOT NULL,
    "lastName" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "department" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "requestedRole" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "requestDate" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "reviewedBy" TEXT,
    "reviewDate" TIMESTAMP(3),
    "reviewNotes" TEXT,

    CONSTRAINT "access_requests_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scan_urls" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "method" TEXT NOT NULL DEFAULT 'GET',
    "statusCode" INTEGER,
    "responseTime" INTEGER,
    "contentType" TEXT,
    "size" INTEGER,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "scan_urls_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "mobile_app_scans" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "hash" TEXT NOT NULL,
    "appName" TEXT NOT NULL,
    "packageName" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "platform" TEXT NOT NULL,
    "fileSize" INTEGER NOT NULL,
    "securityScore" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "permissions" JSONB NOT NULL,
    "trackers" JSONB NOT NULL,
    "domains" JSONB NOT NULL,
    "urls" JSONB NOT NULL,
    "emails" JSONB NOT NULL,
    "mobsfVersion" TEXT,
    "analysisDate" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "mobile_app_scans_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "system_settings" (
    "id" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "description" TEXT,
    "isEncrypted" BOOLEAN NOT NULL DEFAULT false,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "updatedBy" TEXT,

    CONSTRAINT "system_settings_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "mobile_app_scans_scanId_key" ON "mobile_app_scans"("scanId");

-- CreateIndex
CREATE UNIQUE INDEX "system_settings_category_key_key" ON "system_settings"("category", "key");

-- AddForeignKey
ALTER TABLE "scan_urls" ADD CONSTRAINT "scan_urls_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "scans"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "mobile_app_scans" ADD CONSTRAINT "mobile_app_scans_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "scans"("id") ON DELETE CASCADE ON UPDATE CASCADE;
