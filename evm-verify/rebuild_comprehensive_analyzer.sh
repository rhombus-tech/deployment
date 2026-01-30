#!/bin/bash
cd "$(dirname "$0")"
SPLIT_DIR="src/analysis/comprehensive_analyzer_split"
OUT="src/analysis/comprehensive_analyzer.rs"

echo "🔨 Rebuilding comprehensive_analyzer.rs from split files..."
cat "$SPLIT_DIR/part1.rs" \
    "$SPLIT_DIR/part2.rs" \
    "$SPLIT_DIR/part3.rs" \
    "$SPLIT_DIR/part4.rs" > "$OUT"

LINES=$(wc -l < "$OUT")
echo "✅ Done! Generated $OUT ($LINES lines)"
echo ""
echo "Now run: cargo check --lib -p evm-verify"
