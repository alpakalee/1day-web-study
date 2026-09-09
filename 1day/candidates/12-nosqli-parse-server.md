# W12 · NoSQL injection — parse-server (GHSA-vgjh-hmwf-c588)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2026-30941 / 2026-03-11 / high (CVSS4.0 8.7) / parse-server (npm) `>=9.0.0, <9.5.2-alpha.1` 및 `<8.6.14`
- 패치 커밋: advisory에 커밋 링크 없음(릴리스 태그만 제공: `9.5.2-alpha.1`, `8.6.14`). 8.x 라인에서 직전 정식 릴리스와의 diff는 `https://github.com/parse-community/parse-server/compare/8.6.13...8.6.14`
- diff 규모: `src/Routers/UsersRouter.js` +4/-0, `src/Routers/PagesRouter.js` +2/-1 — 2파일 +6/-1 (동일 compare에 changelog/package-lock/스펙 파일 변경도 섞여 있으나 보안 로직은 이 2파일)

## 왜 이 주차에 적절한가
`UsersRouter.handleResetRequest()`(비밀번호 재설정/이메일 인증 재발송 겸용 엔드포인트)는 `const token = req.body?.token;`을 받아 타입 검사 없이 바로 `req.config.database.find('_User', { _perishable_token: token, _perishable_token_expires_at: { $lt: ... } })`에 넣었다. Parse REST API는 JSON 바디를 그대로 받으므로 `token`에 문자열이 아니라 `{"$ne": null}` 같은 MongoDB 연산자 객체를 보내면 `_perishable_token: {$ne: null}` 조건이 되어 "토큰이 null이 아닌 아무 사용자"를 매칭시킬 수 있다. 패치는 `if (token && typeof token !== 'string') throw new Parse.Error(...)`를 추가해 타입을 강제한다. mongoose 건이 `populate.match`처럼 비교적 넓은 쿼리 표면이었다면, 이 건은 "비밀번호 재설정 토큰 조회"라는 아주 좁고 단일 목적인 쿼리에서도 같은 클래스의 연산자 인젝션이 성립한다는 걸 보여줘 12주차 커리큘럼의 폭을 넓힌다.

## 취약점 한 줄 요약
비밀번호 재설정/이메일 인증 재발송 요청 바디의 `token` 필드(문자열 강제 없음)가 MongoDB 쿼리 조건 `_perishable_token: token`에 그대로 들어가, `$ne`/`$gt` 같은 연산자 객체를 주입해 임의 사용자의 미사용 토큰 레코드를 매칭시키는 싱크로 흘러간다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 하. `typeof token !== 'string'`이면 에러를 던지는 가드 4줄이 전부라 "타입 검사 부재 → 연산자 객체가 쿼리에 섞여 들어감"이라는 NoSQLi의 가장 기본적인 패턴을 설명하기에 매우 적합하다. 다만 `_perishable_token`이 무엇이고 이 엔드포인트가 왜 email 없이 token만으로도 사용자를 찾을 수 있는지(비밀번호 재설정 이메일 재발송 시나리오) 배경 설명이 조금 필요하다.
- 재현 환경 구축 부담: 중. Parse Server + MongoDB 로컬 구동이 필요하고, `emailVerifyTokenReuseIfValid` 설정이나 이메일 발송 어댑터 목(mock)까지 갖춰야 advisory가 말하는 "이메일 인증 우회" 임팩트까지 재현 가능하다. 단순히 `$ne` 매칭으로 어떤 사용자가 걸리는지 확인하는 수준이면 REST API 호출(`curl`) 몇 번으로 충분.
- nuclei 템플릿 유무 / PoC 공개 여부: `gh api "/search/code?q=CVE-2026-30941+repo:projectdiscovery/nuclei-templates"` 결과 0건, nuclei 템플릿 없음. 공개 PoC 코드는 확인되지 않음(advisory 본문에 재현 스크립트 없음, 리포터 크레딧만 존재).

## 대안 후보
12-nosqli-mongoose.md(populate match의 `$where`, nuclei 템플릿·OOB PoC 존재, RCE급 임팩트)와 비교하면 이 건은 임팩트가 "계정/토큰 정보 노출·인증 우회" 수준으로 상대적으로 작지만, 공격 표면이 훨씬 좁고 명확해(엔드포인트 하나, 필드 하나) 오히려 "왜 입력 검증이 필요한지"를 가장 압축적으로 보여준다. nuclei 템플릿이 없어 스캐너 데모는 어렵고, 직접 REST 요청으로 시연해야 한다.
