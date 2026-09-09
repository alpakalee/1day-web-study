# W5 · Business logic vulnerabilities — taylored (GHSA-vh5j-5fhq-9xwg)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE 없음(GHSA만 발급) / 2025-06-27 / Low / taylored `<= 8.1.2` (8.1.3에서 패치)
- 패치 커밋: tailot/taylored@fdf67a6fba0deae30912905a79fb5a9e83751a79
- diff 규모: `package.json` +1/-1(버전 범프), `templates/backend-in-a-box/index.js` +22/-15 — 합계 +23/-16, 2파일(핵심 로직 변경은 index.js 39줄, 30줄 기준 초과)

### 포함 기준에 대한 배경
5주차 business logic 카테고리는 GHSA의 CWE 태깅 구조상 후보 자체가 드물다(로직 결함 전용 CWE가 거의 없고, CWE-362/CWE-841처럼 다른 카테고리로 흡수되는 경우가 대부분). 30줄 기준을 정확히 통과하는 후보는 ethyca-fides 한 건뿐이었고, 발표에서 "체크-사용 분리(TOCTOU)로 인한 로직 우회"라는 유형을 open-webui 외에 하나 더 보여주기 위해, 이번 주차에 한해 기준을 40~50줄로 완화하고 이 건(39줄)을 포함시켰다.

## 왜 이 주차에 적절한가
- `/get-patch` 엔드포인트의 취약 로직은 "구매 토큰이 검증(SELECT)과 소비(UPDATE)로 나뉜 두 개의 별도 SQL 문"이라는 가정 하나다. 패치 전 코드는 `db.get(SELECT id, token_used_at FROM purchases WHERE ... AND status = 'COMPLETED', ...)`로 토큰 미사용 여부를 확인한 뒤, 그 결과(`row.token_used_at`)가 null이면 파일을 복호화해 응답을 보내고 **그 이후에** `db.run(UPDATE purchases SET token_used_at = ... WHERE id = ?)`로 토큰을 소비 처리했다. SELECT와 UPDATE 사이에 동시 요청이 끼어들면 둘 다 "미사용" 상태를 관찰하고 둘 다 통과한다.
- 패치는 SELECT+UPDATE 두 단계를 `UPDATE purchases SET token_used_at = CURRENT_TIMESTAMP WHERE patch_id = ? AND purchase_token = ? AND status = 'COMPLETED' AND token_used_at IS NULL` 단일 원자적 문장으로 합치고 `this.changes === 0`이면 거부하도록 바꿔, "검증과 소비를 하나의 원자적 연산으로 묶는다"는 레이스컨디션 표준 해법을 그대로 보여준다. open-webui의 "check와 insert를 분리하지 말라"는 교훈과 동일 구조라 두 사례를 나란히 놓고 패턴을 일반화하기 좋다.
- 공격 시나리오도 "결제 토큰 1회권을 동시 요청으로 재사용해 유료 콘텐츠(patch)를 복제 취득"이라는 비즈니스 임팩트(수익 손실)가 명확해 초심자에게 "이게 왜 문제인가"를 설명하기 쉽다.

## 취약점 한 줄 요약
`/get-patch` 요청의 구매 토큰(입력)이 별도의 SELECT로 미사용 여부만 확인된 뒤, 파일 복호화·응답 이후에야 별도의 UPDATE(싱크)로 소비 처리되어 — 두 요청을 동시에 보내면 둘 다 SELECT를 통과해 하나의 토큰으로 유료 patch 파일을 두 번 받을 수 있다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 39줄이지만 실제로 봐야 할 변화는 "SELECT 후 조건 분기 후 UPDATE"였던 3단계를 "조건까지 포함한 단일 UPDATE + `this.changes` 확인"으로 합친 것 하나뿐이다. 나머지 diff는 콜백 중첩 제거(들여쓰기 정리)라 실질 로직 변경분은 적다. 다만 SQL 콜백 스타일(`db.get`/`db.run` 콜백)에 익숙하지 않으면 diff 자체의 가독성은 open-webui보다 떨어진다.
- 재현 환경 구축 부담: `templates/backend-in-a-box`는 Express+sqlite3 단일 파일 서버라 로컬 설치·기동이 가볍다. 레이스컨디션 재현은 Burp Repeater의 "Send group in parallel"이나 간단한 병렬 curl/스크립트로 SQLite 파일 기반 서버에서도 바로 트리거 가능해, open-webui(LDAP/OAuth 목업 필요)보다 재현 부담이 훨씬 낮다.
- nuclei 템플릿 유무 / PoC 공개 여부: CVE가 배정되지 않아 nuclei-templates 검색 대상에서 제외(작업 절차상 생략). advisory 자체가 신고자의 재현 절차(동시 요청 2개, PoC 코드 스니펫 포함)를 상세히 제공해 별도 PoC 코드 확보 없이도 advisory만으로 재현 로직을 구성할 수 있다.

## 대안 후보
open-webui(GHSA-h3ww-q6xx-w7x3, high, 25줄, LDAP/OAuth admin 승격 레이스)와 같은 "체크-사용 분리" 구조지만, taylored는 (a) 재현 환경이 Express+SQLite 단일 파일이라 훨씬 가볍고 (b) SQL 문 자체를 원자화하는 해법이 더 명료해 "왜 이렇게 고쳐야 하는가"를 코드 레벨에서 바로 증명할 수 있다. 반면 severity는 low로 세 후보(open-webui/ethyca-fides/taylored) 중 가장 낮고 CVE 미배정이라 "실제로 얼마나 심각한가"를 이야기할 때는 다른 두 건보다 설득력이 약하다는 점을 발표에서 밝혀야 한다.
