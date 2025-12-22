const fs = require('fs');
const path = require('path');

// Frontend dizini
const targetDir = path.join(__dirname, '../frontend/src');

// Silinecek console pattern'leri
const REMOVE_PATTERNS = [
  /console\.log\([^)]*\);?\s*$/gm,
  /console\.warn\([^)]*\);?\s*$/gm,
  /console\.debug\([^)]*\);?\s*$/gm
];

// Korunacak pattern'ler (error ve özel logger wrapper'ları)
const KEEP_PATTERNS = [
  /console\.error/,
  /\/\/ to log results/  // index.tsx'deki yorum satırı
];

/**
 * Bir dosyadaki console.log satırlarını temizle
 */
function cleanupFile(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split('\n');
  const cleanedLines = [];
  let removedCount = 0;

  for (const line of lines) {
    // Korunması gereken satırları kontrol et
    const shouldKeep = KEEP_PATTERNS.some(pattern => pattern.test(line));
    
    if (shouldKeep) {
      cleanedLines.push(line);
      continue;
    }

    // Silinmesi gereken pattern'leri kontrol et
    const shouldRemove = REMOVE_PATTERNS.some(pattern => pattern.test(line));
    
    if (shouldRemove) {
      removedCount++;
      continue; // Satırı ekleme
    }

    cleanedLines.push(line);
  }

  // Dosyayı güncelle
  if (removedCount > 0) {
    fs.writeFileSync(filePath, cleanedLines.join('\n'), 'utf8');
  }

  return removedCount;
}

/**
 * Dizini recursive olarak tara
 */
function walkDirectory(dir, extensions = ['.ts', '.tsx']) {
  const files = fs.readdirSync(dir);
  let totalRemoved = 0;
  let filesModified = 0;

  files.forEach(file => {
    const filePath = path.join(dir, file);
    const stat = fs.statSync(filePath);

    if (stat.isDirectory()) {
      // node_modules, build, dist gibi dizinleri atla
      if (!['node_modules', 'build', 'dist', '.git'].includes(file)) {
        const result = walkDirectory(filePath, extensions);
        totalRemoved += result.totalRemoved;
        filesModified += result.filesModified;
      }
    } else if (extensions.some(ext => filePath.endsWith(ext))) {
      const removed = cleanupFile(filePath);
      if (removed > 0) {
        console.log(`✅ ${path.relative(targetDir, filePath)}: Removed ${removed} console logs`);
        totalRemoved += removed;
        filesModified++;
      }
    }
  });

  return { totalRemoved, filesModified };
}

// Ana işlemi başlat
console.log('🧹 Starting FRONTEND console.log cleanup...');
console.log('📁 Scanning:', targetDir);
console.log('🎯 Target: Remove console.log, console.warn, console.debug');
console.log('✅ Keep: console.error\n');

const { totalRemoved, filesModified } = walkDirectory(targetDir);

console.log('\n📊 Cleanup Summary:');
console.log(`   Files modified: ${filesModified}`);
console.log(`   Lines removed: ${totalRemoved}`);
console.log('\n✨ Frontend cleanup complete!');
