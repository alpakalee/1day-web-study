import json, glob, os, collections
import os
os.makedirs("tmp", exist_ok=True)

sized = {r["ghsa"]: r for r in json.load(open("tmp/sized.json"))}
NAMES = {"79":"XSS","89":"SQLi","352":"CSRF","22":"Path Traversal","434":"File Upload",
 "918":"SSRF","611":"XXE","78":"OS Command Inj","77":"Command Inj","94":"Code Inj",
 "1336":"SSTI","502":"Deserialization","287":"Authentication","863":"Access Control",
 "639":"IDOR","362":"Race Condition","770":"Resource Limit","601":"Open Redirect",
 "209":"Info Disclosure","74":"Injection(generic)"}

def good(r):
    s = r.get("stats")
    if not s: return False
    tot = s["core_add"] + s["core_del"]
    return 1 <= tot <= 30 and 1 <= s["files_core"] <= 3

print(f"{'CWE':<6}{'name':<18}{'adv':>5}{'commit':>8}{'small':>7}")
rows = {}
for f in sorted(glob.glob("tmp/adv_pip_*.json")):
    cwe = os.path.basename(f)[8:-5]
    advs = json.load(open(f))
    ids = [a["ghsa_id"] for a in advs]
    withc = [i for i in ids if sized.get(i, {}).get("stats")]
    small = [i for i in ids if i in sized and good(sized[i])]
    rows[cwe] = (len(ids), len(withc), len(small), small)
    print(f"{cwe:<6}{NAMES.get(cwe,'?'):<18}{len(ids):>5}{len(withc):>8}{len(small):>7}")

json.dump({k: v[3] for k, v in rows.items()}, open("tmp/small_by_cwe.json", "w"), indent=1)
