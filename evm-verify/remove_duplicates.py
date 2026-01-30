#!/usr/bin/env python3
import re

# Read the file
with open('src/analysis/vulnerability_validator.rs', 'r') as f:
    lines = f.readlines()

# Find all validate_* method definitions with their line numbers
methods = {}
for i, line in enumerate(lines):
    match = re.search(r'pub fn (validate_\w+)\(&self', line)
    if match:
        method_name = match.group(1)
        if method_name not in methods:
            methods[method_name] = []
        methods[method_name].append(i)

# Find duplicates
duplicates = {name: locs for name, locs in methods.items() if len(locs) > 1}

print(f"Found {len(duplicates)} methods with duplicates:")
for name in sorted(duplicates.keys())[:10]:
    locs = duplicates[name]
    print(f"  {name}: lines {[l+1 for l in locs]}")

# Strategy: Keep first occurrence, mark all others for deletion
lines_to_delete = set()
for name, locs in duplicates.items():
    # Keep first, delete rest
    for loc in locs[1:]:
        # Find the complete method (from pub fn to closing brace)
        start = loc
        end = loc + 1
        brace_count = 0
        started = False
        for j in range(loc, min(loc + 20, len(lines))):
            if '{' in lines[j]:
                started = True
                brace_count += lines[j].count('{')
            if started:
                brace_count -= lines[j].count('}')
                if brace_count == 0:
                    end = j + 1
                    break
        
        for k in range(start, end):
            lines_to_delete.add(k)

print(f"\nWill delete {len(lines_to_delete)} lines")

# Create new content with duplicates removed
new_lines = [line for i, line in enumerate(lines) if i not in lines_to_delete]

# Write back
with open('src/analysis/vulnerability_validator.rs', 'w') as f:
    f.writelines(new_lines)

print("Done! Duplicates removed.")
