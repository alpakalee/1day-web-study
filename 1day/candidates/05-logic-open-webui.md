# W5 · Business logic vulnerabilities — open-webui (GHSA-h3ww-q6xx-w7x3)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2026-45675 / 2026-05-14 / High (CVSS 8.1) / open-webui `<= 0.8.12` (0.9.0에서 패치)
- 패치 커밋: open-webui/open-webui@96a0b3239b1aadb23fc359bf10849c9ba12fd6ec (PR #23626)
- diff 규모: `backend/open_webui/routers/auths.py` +9/-3, `backend/open_webui/utils/oauth.py` +16/-3 — 합계 +25/-6, 2파일

## 왜 이 주차에 적절한가
- 취약 로직은 "DB에 사용자가 0명이면 최초 로그인자를 admin으로 만든다"는 비즈니스 규칙 하나다. LDAP 경로(`auths.py` 482행)는 `role = 'admin' if not Users.has_users(db=db) else DEFAULT_USER_ROLE`로 역할을 **먼저 결정**하고 484행에서 그 값으로 `insert_new_auth`를 호출한다. OAuth 경로(`oauth.py` `get_user_role`)도 `user_count = Users.get_num_users(); if not user and user_count == 0: return 'admin'`로 동일한 패턴이다. 즉 "확인(check)"과 "사용(use)"이 별도 요청/트랜잭션으로 쪼개져 있어 동시 요청이 둘 다 "사용자 0명"을 관찰할 수 있다.
- PortSwigger Business logic 카테고리의 핵심 랩 유형인 "high-level logic vulnerability(가정이 깨지는 지점)"와 "race condition을 이용한 로직 우회"에 정확히 대응한다. 패치가 이미 존재하는 `signup_handler`(auths.py 663행, "Insert with default role first to avoid TOCTOU race" 주석)를 LDAP/OAuth 경로에만 빠뜨린 구조라, "한 곳은 고쳤는데 다른 진입점은 놓쳤다"는 로직 결함의 전형을 보여준다.
- CWE 태깅은 CWE-269(Improper Privilege Management) + CWE-362(Race Condition)로 걸려 있으나, 이번 주차처럼 "로직 결함" 자체를 주제로 잡을 때는 CWE 카테고리보다 "가정이 무엇이고 왜 깨지는가"를 설명하는 것이 발표 구성에 더 적합하다.

## 취약점 한 줄 요약
LDAP/OAuth 첫 로그인 요청(입력: 인증 성공 후 신규 계정 생성 트리거)이 각자 `has_users()`/`get_num_users()`로 "사용자 0명" 여부를 체크하고, 그 결과를 `role` 값으로 `Auths.insert_new_auth()`(싱크)에 그대로 넘긴다 — 체크와 삽입 사이에 동시 요청이 끼어들면 여러 계정이 동시에 admin 역할로 생성된다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 25줄로 30줄 기준선에 근접하지만, 실제로 봐야 할 로직은 "역할을 insert 전에 정하느냐 후에 정하느냐" 한 가지뿐이다. `auths.py`는 role 계산을 삭제하고 무조건 `DEFAULT_USER_ROLE`로 insert한 뒤 `if Users.get_num_users(db=db) == 1: update_user_role_by_id(..., 'admin')`를 추가한 대칭 구조라 diff 자체는 읽기 쉽다. 부담 요소는 `oauth.py` 쪽 훅이 두 군데(role 결정부 `get_user_role`, 실제 insert 이후 승격 로직)로 나뉘어 있어 LDAP 한 곳만 보는 auths.py보다 흐름 추적에 시간이 더 든다는 점 — 발표에서는 auths.py(LDAP)만 화면에 띄우고 oauth.py는 "동일 패턴 반복"으로 요약하는 편이 15분에 맞는다.
- 재현 환경 구축 부담: LDAP 서버 또는 OAuth IdP를 별도로 띄워야 레이스를 실제로 트리거할 수 있어, 학생 노트북에서 즉석 재현은 부담이 크다. Burp Repeater의 "Send group in parallel"로 개념만 보여주는 것이 현실적(실제 LDAP/OAuth 목업 없이는 엔드투엔드 재현 불가).
- nuclei 템플릿 유무 / PoC 공개 여부: `projectdiscovery/nuclei-templates` 코드 검색 결과 CVE-2026-45675 매칭 0건. 공개 PoC 익스플로잇 코드는 advisory 본문에 별도로 없음(레이스 조건 설명과 패치 diff만 제공).

## 대안 후보
이번 주차는 애초에 CWE 태깅이 잘 안 되는 카테고리라 후보 자체가 적었다. 30줄 기준을 통과한 8건 중 진짜로 이 기준에 여유 있게 들어온 것은 Ethyca Fides(GHSA-qx5f-ghc2-7g5c / CVE-2026-42303, medium, +15/-3 2파일)뿐이었다 — "중복요청 탐지 시 신원 재검증을 스킵하는" 워크플로우 검증 누락으로, diff 크기만 보면 이쪽이 발표 난이도에는 더 안전하다. 다만 severity가 medium이고 "왜 그 검증을 건너뛰면 위험한가"를 설명하려면 서비스의 워크플로우 상태 머신 전체 맥락을 먼저 깔아야 해서, 레이스 컨디션처럼 즉각 직관적인 "동시 요청 → 가정 붕괴" 그림이 나오지 않는다. open-webui 건은 25줄로 기준을 살짝 넘지만 (a) severity가 high로 이번 주 임팩트를 보여주기 좋고 (b) "체크-사용 분리"라는 로직 결함의 교과서적 형태를 already-patched 코드(signup_handler)와 나란히 대조해서 설명할 수 있어, 기준 초과분을 감수할 값어치가 있다고 판단해 이쪽을 채택했다.
