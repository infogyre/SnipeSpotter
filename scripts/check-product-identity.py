#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[1]
checks = {
    root / "spotter-core/src/identity.rs": ('"SnipeSpotter"', '"infogyre"'),
    root / "installer/installer.en-us.wxl": ('Value="SnipeSpotter"', 'Value="infogyre"'),
    root / "installer/Product.wxs": ('!(loc.ProductName)', '!(loc.Manufacturer)'),
}
for path, needles in checks.items():
    text = path.read_text(encoding="utf-8")
    for needle in needles:
        if needle not in text:
            raise SystemExit(f"{path}: missing identity value {needle}")
print("product identity is consistent")
