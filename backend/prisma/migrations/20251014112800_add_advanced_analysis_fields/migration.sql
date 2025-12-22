/*
  Warnings:

  - The `metadata` column on the `scans` table would be dropped and recreated. This will lead to data loss if there is data in the column.

*/
-- AlterTable
ALTER TABLE "scans" ADD COLUMN     "advancedAnalysis" JSONB,
ADD COLUMN     "apiSecurity" JSONB,
ADD COLUMN     "jsSecurity" JSONB,
DROP COLUMN "metadata",
ADD COLUMN     "metadata" JSONB;
