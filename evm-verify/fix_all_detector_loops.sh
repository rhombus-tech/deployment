#!/bin/bash

cd /Users/talzisckind/Downloads/deployment/evm-verify/src/analysis

# Fix all detector files with i+1..i+N patterns
for file in *.rs; do
    echo "Fixing $file..."
    # Fix patterns like: for j in i+1..i+40
    sed -i '' 's/for \([a-z]\) in \([a-z]\)+1\.\.\2+\([0-9]*\)/for \1 in (\2+1)..(\2+\3)/g' "$file"
    # Add bounds check after the for loop line
    sed -i '' '/for [a-z] in ([a-z]+1)\.\.([a-z]+[0-9]*)/a\
                    if j >= self.bytecode.len() { break; }
' "$file" 2>/dev/null || true
done

echo "Fixed all detector loop patterns!"
