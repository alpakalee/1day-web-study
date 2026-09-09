# GHSA 후보 선별 스크립트

매주 그 주 CWE로 최근 패치를 찾아 diff를 읽는다. CVE를 많이 보는 게 목적이 아니라, 랩에서 본 패턴이 실제 코드에서 어떤 모양인지 한 번 확인하는 것이다.

## 후보 조건

1. 공개 3년 이내 GitHub-reviewed advisory
2. 해당 주차 CWE (또는 CWE 태깅이 안 되는 카테고리는 키워드 필터로 보완)
3. 패치 커밋이 공개돼 있을 것
4. 테스트·문서·락파일을 뺀 실코드 변경이 30줄 이하, 3파일 이하
5. pip 생태계 우선 — 후보가 마르면 npm/maven으로 전환

4번이 핵심이다. 15분 발표에서 diff 300줄은 읽히지 않는다. 5줄짜리 패치를 골라야 "왜 이 5줄인가"에 시간을 다 쓸 수 있다.

## 실행

```bash
python tools/ghsa_count.py pip 2023-01-01    # CWE별 advisory 수집
python tools/ghsa_size.py tmp/adv_pip_89.json # 특정 CWE의 diff 규모 필터
python tools/ghsa_size.py tmp/adv_pip_*.json  # 전량
python tools/ghsa_bycwe.py                    # CWE별 수율 표
```

`gh auth login`이 되어 있어야 한다. CWE 하나에 API 40~60회를 쓰고 한도는 시간당 5000회다.
Python 후보가 마르는 주차는 첫 인자를 `npm`이나 `maven`으로 바꾼다.
CWE 태깅 자체가 없는 카테고리(business logic 등)는 `gh api`로 전체 advisory를 받아 summary/description 텍스트를 키워드로 필터링해야 한다 — `tools/ghsa_count.py`의 `CWES` 딕셔너리에 없는 CWE(943, 862, 915 등)도 같은 방식으로 직접 조회한다.

## 수율 (2026-09-07 측정, pip, CWE 20종, 당시 기준 2026-01-01 이후)

```
advisory 1111건 → 패치 커밋 링크 있음 498건 → 실코드 30줄·3파일 이하 216건
```

절반 이상은 advisory에 커밋 링크가 없어 자동으로 걸러진다. 남은 것의 43%가 소규모 패치였다.

| CWE | 유형 | advisory | 커밋 | 소규모 |
|---|---|---|---|---|
| 22 | Path traversal | 218 | 106 | 54 |
| 79 | XSS | 107 | 46 | 28 |
| 770 | Resource limit | 68 | 42 | 21 |
| 918 | SSRF | 155 | 78 | 17 |
| 502 | Deserialization | 80 | 27 | 13 |
| 94 | Code injection | 92 | 42 | 12 |
| 863 | Access control | 79 | 19 | 11 |
| 639 | IDOR | 64 | 26 | 10 |
| 89 | SQLi | 36 | 18 | 8 |
| 74 | Injection (generic) | 31 | 17 | 8 |
| 78 | OS command injection | 51 | 23 | 7 |
| 287 | Authentication | 33 | 13 | 6 |
| 601 | Open redirect | 22 | 9 | 5 |
| 352 | CSRF | 14 | 8 | 4 |
| 1336 | SSTI | 18 | 7 | 2 |
| 362 | Race condition | 9 | 5 | 2 |
| 434 | File upload | 8 | 3 | 2 |
| 77 | Command injection | 15 | 6 | 2 |
| 209 | Info disclosure | 7 | 3 | 2 |
| 611 | XXE | 4 | 0 | 0 |

CWE 태깅이 아예 없거나(business logic) 생태계에 후보가 없는 경우(XXE, NoSQLi)는 3주기(5, 10, 12주) 조사에서 별도로 확인했다 — 결과는 `1day/README.md` 참조.
