#!/bin/bash
cd "$(dirname "$0")"
cat src/analysis/comprehensive_analyzer_split/part{1,2,3,4}.rs > src/analysis/comprehensive_analyzer.rs
echo "Concatenated into comprehensive_analyzer.rs ($(wc -l < src/analysis/comprehensive_analyzer.rs) lines)"
