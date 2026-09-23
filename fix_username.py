import os
from pathlib import Path

OLD = "meysamkhademshams"
NEW = "khademdev"

files = [
    "README.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "Makefile",
    "build.sh",
    ".github/workflows/release.yml",
    ".github/workflows/ci.yml",
]

count = 0
for name in files:
    p = Path(name)
    if not p.exists():
        continue
    text = p.read_text(encoding="utf-8")
    if OLD in text:
        n = text.count(OLD)
        text = text.replace(OLD, NEW)
        p.write_text(text, encoding="utf-8")
        print(f"  [ ok ] {name}  ({n} replacements)")
        count += 1
    else:
        print(f"  [skip] {name}  (no match)")

print()
print(f"Done. {count} files updated.")