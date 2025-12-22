const fs = require('fs');
const path = require('path');

// Silinecek console log tipleri
const REMOVE_PATTERNS = [
  /console\.log\([^)]*\);?\s*$/gm,  // console.log
  /console\.warn\([^)]*\);?\s*$/gm, // console.warn
  /console\.debug\([^)]*\);?\s*$/gm // console.debug
];

// Tutulacak (sadece console.error)
const KEEP_PATTERNS = [
  /console\.error/
];

function cleanupFile(filePath) {
  try {
    let content = fs.readFileSync(filePath, 'utf8');
    let originalLength = content.length;
    let linesRemoved = 0;
    
    // Her satırı kontrol et
    const lines = content.split('\n');
    const newLines = lines.filter(line => {
      // console.error varsa kalsın
      if (KEEP_PATTERNS.some(pattern => pattern.test(line))) {
        return true;
      }
      
      // Diğer console log'ları sil
      const shouldRemove = REMOVE_PATTERNS.some(pattern => pattern.test(line.trim()));
      if (shouldRemove) {
        linesRemoved++;
        return false;
      }
      
      return true;
    });
    
    const newContent = newLines.join('\n');
    
    if (newContent !== content) {
      fs.writeFileSync(filePath, newContent, 'utf8');
      console.log(`✅ ${path.basename(filePath)}: Removed ${linesRemoved} console logs`);
      return linesRemoved;
    }
    
    return 0;
  } catch (error) {
    console.error(`❌ Error processing ${filePath}:`, error.message);
    return 0;
  }
}

function walkDirectory(dir, extensions = ['.ts', '.js']) {
  let totalRemoved = 0;
  let filesProcessed = 0;
  
  const files = fs.readdirSync(dir);
  
  files.forEach(file => {
    const filePath = path.join(dir, file);
    const stat = fs.statSync(filePath);
    
    if (stat.isDirectory()) {
      // Skip node_modules and build directories
      if (!['node_modules', 'dist', 'build', '.git'].includes(file)) {
        const result = walkDirectory(filePath, extensions);
        totalRemoved += result.removed;
        filesProcessed += result.files;
      }
    } else if (extensions.some(ext => file.endsWith(ext))) {
      const removed = cleanupFile(filePath);
      if (removed > 0) {
        totalRemoved += removed;
        filesProcessed++;
      }
    }
  });
  
  return { removed: totalRemoved, files: filesProcessed };
}

// Ana işlem
const backendSrc = path.join(__dirname, '..', 'backend', 'src');

console.log('🧹 Starting console.log cleanup...\n');
console.log('📁 Scanning:', backendSrc);
console.log('🎯 Target: Remove console.log, console.warn, console.debug');
console.log('✅ Keep: console.error\n');

const result = walkDirectory(backendSrc);

console.log('\n📊 Cleanup Summary:');
console.log(`   Files modified: ${result.files}`);
console.log(`   Lines removed: ${result.removed}`);
console.log('\n✨ Cleanup complete!');
