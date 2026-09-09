import json, re, subprocess, sys, os
import os
os.makedirs("tmp", exist_ok=True)

COMMIT_RE = re.compile(r"https://github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{7,40})")
SKIP = re.compile(r"(^|/)(tests?|testing|spec|__tests__)/|(^|/)test_|_test\.|"
                  r"\.lock$|package-lock\.json|yarn\.lock|poetry\.lock|"
                  r"CHANGELOG|\.md$|\.txt$|\.rst$|\.po$|\.min\.js$")

def gh(path):
    r = subprocess.run(["gh","api",path], capture_output=True, text=True, encoding="utf-8")
    return json.loads(r.stdout) if r.returncode == 0 else None

def commit_stats(owner, repo, sha):
    c = gh(f"/repos/{owner}/{repo}/commits/{sha}")
    if not c or "files" not in c: return None
    core = [f for f in c["files"] if not SKIP.search(f["filename"])]
    return {
        "files_all": len(c["files"]),
        "files_core": len(core),
        "core_add": sum(f.get("additions",0) for f in core),
        "core_del": sum(f.get("deletions",0) for f in core),
        "paths": [f["filename"] for f in core][:5],
    }

rows = []
for path in sys.argv[1:]:
    for a in json.load(open(path)):
        m = None
        for ref in a.get("references", []):
            m = COMMIT_RE.match(ref)
            if m: break
        if not m:
            rows.append({"ghsa": a["ghsa_id"], "cve": a.get("cve_id"), "sev": a["severity"],
                         "pkg": a["vulnerabilities"][0]["package"]["name"] if a.get("vulnerabilities") else None,
                         "pub": a["published_at"][:10], "commit": None, "stats": None,
                         "summary": a["summary"][:90]})
            continue
        o, r_, sha = m.groups()
        rows.append({"ghsa": a["ghsa_id"], "cve": a.get("cve_id"), "sev": a["severity"],
                     "pkg": a["vulnerabilities"][0]["package"]["name"] if a.get("vulnerabilities") else None,
                     "pub": a["published_at"][:10], "commit": m.group(0),
                     "stats": commit_stats(o, r_, sha), "summary": a["summary"][:90]})

json.dump(rows, open("tmp/sized.json","w"), indent=1)
n = len(rows)
withc = [r for r in rows if r["stats"]]
tiny = [r for r in withc
        if 1 <= r["stats"]["core_add"] + r["stats"]["core_del"] <= 30
        and 1 <= r["stats"]["files_core"] <= 3]
print(f"advisory {n}건 / commit 링크+조회성공 {len(withc)}건 / 실코드 30줄·3파일 이하 {len(tiny)}건")
for r in sorted(tiny, key=lambda x: x["stats"]["core_add"]+x["stats"]["core_del"])[:15]:
    s = r["stats"]
    print(f"  {r['pub']} {r['ghsa']} {r['sev']:<8} {str(r['pkg'])[:22]:<22} "
          f"+{s['core_add']}/-{s['core_del']} {s['files_core']}f | {r['summary'][:55]}")
