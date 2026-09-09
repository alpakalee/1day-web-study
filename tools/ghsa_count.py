import json, subprocess, sys
import os
os.makedirs("tmp", exist_ok=True)

CWES = {
    "79":"XSS","89":"SQLi","352":"CSRF","22":"Path Traversal","434":"File Upload",
    "918":"SSRF","611":"XXE","78":"OS Command Injection","77":"Command Injection",
    "94":"Code Injection","1336":"SSTI","502":"Deserialization","287":"Authentication",
    "863":"Access Control","639":"IDOR","362":"Race Condition","770":"Resource Limit",
    "601":"Open Redirect","209":"Info Disclosure","74":"Injection(generic)",
}

def api(path):
    r = subprocess.run(["gh","api",path,"--paginate","--slurp"],
                       capture_output=True, text=True, encoding="utf-8")
    if r.returncode:
        print(r.stderr[:300], file=sys.stderr)
        return []
    return [a for page in json.loads(r.stdout) for a in page]

eco = sys.argv[1] if len(sys.argv) > 1 else "pip"
since = sys.argv[2] if len(sys.argv) > 2 else "2026-01-01"

print(f"{'CWE':<6}{'name':<24}{'count':>6}")
total = 0
for cwe, name in CWES.items():
    advs = api(f"/advisories?type=reviewed&ecosystem={eco}&cwes={cwe}&published=%3E%3D{since}&per_page=100")
    total += len(advs)
    print(f"{cwe:<6}{name:<24}{len(advs):>6}")
    json.dump(advs, open(f"tmp/adv_{eco}_{cwe}.json", "w"))
print(f"{'':<6}{'TOTAL(dup incl)':<24}{total:>6}")
