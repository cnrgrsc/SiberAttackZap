-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "NotificationType" ADD VALUE 'SCAN_QUEUED';
ALTER TYPE "NotificationType" ADD VALUE 'SCAN_DEQUEUED';

-- AlterTable
ALTER TABLE "scans" ADD COLUMN     "queuePosition" INTEGER,
ADD COLUMN     "queuePriority" INTEGER DEFAULT 5,
ADD COLUMN     "queuedAt" TIMESTAMP(3);

-- CreateTable
CREATE TABLE "scan_queue" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "priority" INTEGER NOT NULL DEFAULT 5,
    "addedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "estimatedStart" TIMESTAMP(3),

    CONSTRAINT "scan_queue_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "scan_queue_scanId_key" ON "scan_queue"("scanId");

-- CreateIndex
CREATE INDEX "scan_queue_priority_addedAt_idx" ON "scan_queue"("priority", "addedAt");

-- AddForeignKey
ALTER TABLE "scan_queue" ADD CONSTRAINT "scan_queue_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "scans"("id") ON DELETE CASCADE ON UPDATE CASCADE;
