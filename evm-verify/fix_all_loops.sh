#!/bin/bash

cd /Users/talzisckind/Downloads/deployment/evm-verify/src/analysis

# Fix all remaining loop variable errors with parentheses
find . -name "*.rs" -type f -exec sed -i '' 's/for k in j+1\.\.k+\([0-9]*\)/for k in j+1..(j+\1)/g' {} \;
find . -name "*.rs" -type f -exec sed -i '' 's/for m in k+1\.\.m+\([0-9]*\)/for m in k+1..(k+\1)/g' {} \;
find . -name "*.rs" -type f -exec sed -i '' 's/for n in m+1\.\.n+\([0-9]*\)/for n in m+1..(m+\1)/g' {} \;
find . -name "*.rs" -type f -exec sed -i '' 's/for m in j+1\.\.m+\([0-9]*\)/for m in j+1..(j+\1)/g' {} \;
find . -name "*.rs" -type f -exec sed -i '' 's/for k in i+1\.\.k+\([0-9]*\)/for k in i+1..(i+\1)/g' {} \;
find . -name "*.rs" -type f -exec sed -i '' 's/for m in i+1\.\.m+\([0-9]*\)/for m in i+1..(i+\1)/g' {} \;
find . -name "*.rs" -type f -exec sed -i '' 's/for n in i+1\.\.n+\([0-9]*\)/for n in i+1..(i+\1)/g' {} \;
find . -name "*.rs" -type f -exec sed -i '' 's/for n in j+1\.\.n+\([0-9]*\)/for n in j+1..(j+\1)/g' {} \;

echo "Fixed all loop variables"
