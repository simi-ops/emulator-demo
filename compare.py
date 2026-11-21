#!/usr/bin/env python3
"""Diff results-emu.json against results-aws.json (real AWS is the reference)."""
import json, sys
emu = json.load(open("results-emu.json"))["results"]
aws = json.load(open("results-aws.json"))["results"]
E = {(r["group"], r["step"]): r for r in emu}
A = {(r["group"], r["step"]): r for r in aws}

def classify(a, e):
    if e is None: return "MISSING_IN_EMU", "step did not run"
    if a["ok"] != e["ok"]:
        if a["ok"]: return "OUTCOME", f"AWS ok, emulator error {e.get('code')}"
        return "OUTCOME", f"AWS error {a.get('code')}, emulator succeeded"
    if not a["ok"]:
        if a.get("code") != e.get("code"): return "ERROR_CODE", f"AWS {a.get('code')} vs emulator {e.get('code')}"
        if a.get("status") != e.get("status"): return "HTTP_STATUS", f"AWS {a.get('status')} vs emulator {e.get('status')}"
        if a.get("msg") != e.get("msg"): return "MESSAGE", f"AWS: {str(a.get("msg"))[:110]!r}\n        EMU: {str(e.get("msg"))[:110]!r}"
        if a.get("extra") != e.get("extra"): return "ERROR_EXTRA", f"AWS {json.dumps(a.get('extra'))[:140]} vs EMU {json.dumps(e.get('extra'))[:140]}"
        return "SAME", ""
    if a.get("keys") != e.get("keys"): return "RESPONSE_KEYS", f"AWS-only {sorted(set(a.get('keys') or []) - set(e.get('keys') or []))} EMU-only {sorted(set(e.get('keys') or []) - set(a.get('keys') or []))}"
    if a.get("val") != e.get("val"): return "VALUE", f"AWS {json.dumps(a.get('val'))[:200]}\n        EMU {json.dumps(e.get('val'))[:200]}"
    return "SAME", ""

rows = []
for k, a in A.items():
    c, d = classify(a, E.get(k))
    rows.append((k, c, d))
from collections import Counter, defaultdict
tot = Counter(c for _, c, _ in rows)
print("TOTAL", len(rows), dict(tot))
by = defaultdict(Counter)
for (g, s), c, d in rows: by[g][c] += 1
for g, cnt in by.items():
    n = sum(cnt.values()); print(f"  {g:16s} {cnt['SAME']}/{n} identical   " + ", ".join(f"{c}={v}" for c, v in cnt.items() if c != "SAME"))
print()
for (g, s), c, d in rows:
    if c != "SAME": print(f"[{c}] {g}/{s}\n        {d}")
json.dump([{"group": g, "step": s, "class": c, "detail": d} for (g, s), c, d in rows], open("diff.json", "w"), indent=1)
