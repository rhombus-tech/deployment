#!/bin/bash

# Fix all loop variable scoping errors in detector files

cd /Users/talzisckind/Downloads/deployment/evm-verify/src/analysis

# Pattern 1: for k in j+1..j+10 -> for k in j+1..(j+10).min(self.bytecode.len())
find . -name "*_detector.rs" -exec sed -i '' 's/for k in j+1\.\.j+\([0-9]*\)/for k in j+1..(j+\1).min(self.bytecode.len())/g' {} \;

# Pattern 2: for m in k+1..k+10 -> for m in k+1..(k+10).min(self.bytecode.len())
find . -name "*_detector.rs" -exec sed -i '' 's/for m in k+1\.\.k+\([0-9]*\)/for m in k+1..(k+\1).min(self.bytecode.len())/g' {} \;

# Pattern 3: for n in m+1..m+10 -> for n in m+1..(m+10).min(self.bytecode.len())
find . -name "*_detector.rs" -exec sed -i '' 's/for n in m+1\.\.m+\([0-9]*\)/for n in m+1..(m+\1).min(self.bytecode.len())/g' {} \;

# Pattern 4: for k in i+1..k+10 (typo) -> for k in i+1..(i+10).min(self.bytecode.len())
find . -name "*_detector.rs" -exec sed -i '' 's/for k in i+1\.\.k+\([0-9]*\)/for k in i+1..(i+\1).min(self.bytecode.len())/g' {} \;

# Pattern 5: for m in j+1..m+10 (typo) -> for m in j+1..(j+10).min(self.bytecode.len())
find . -name "*_detector.rs" -exec sed -i '' 's/for m in j+1\.\.m+\([0-9]*\)/for m in j+1..(j+\1).min(self.bytecode.len())/g' {} \;

# Pattern 6: for m in i+1..m+10 (typo) -> for m in i+1..(i+10).min(self.bytecode.len())
find . -name "*_detector.rs" -exec sed -i '' 's/for m in i+1\.\.m+\([0-9]*\)/for m in i+1..(i+\1).min(self.bytecode.len())/g' {} \;

echo "Fixed all loop variable scoping errors"
