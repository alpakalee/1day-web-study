# W2 · Authentication — sentry (GHSA-7pq6-v88g-wf3w)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2025-22146 / 2025-01-15 / critical (CVSS3 9.1) / sentry `>=21.12.0, <25.1.0`, 패치 `25.1.0`
- 패치 커밋: https://github.com/getsentry/sentry/commit/6db508f7949d117c7dff748a3c82c3a272bf7cfd
- diff 규모: 핸들러 파일 1파일 +1/-1

## 왜 이 주차에 적절한가
SAML ACS(Assertion Consumer Service) 콜백 처리 로직인 `handle_unknown_identity()`에서, 기존 계정에 SSO 신원을 연결(link)할지 판단하는 조건이 `op == "confirm" and self.user.is_authenticated or is_account_verified`였다. `self.user.is_authenticated`는 "현재 세션에 로그인된 어떤 사용자가 있는가"만 확인할 뿐, 그 로그인된 사용자가 SAML 어설션이 가리키는 이메일의 소유자(`self.user`, IdP가 응답한 대상 계정)와 실제로 동일 인물인지는 검사하지 않는다. 즉 공격자가 본인 세션(자기 조직의 SAML)으로 로그인한 상태에서 피해자 이메일을 아는 것만으로 다른 조직의 계정에 신원을 연결해 로그인 우회가 가능했다. 패치는 이 조건을 `self.request.user.id == self.user.id`로 바꿔 "로그인 여부"가 아니라 "요청을 보낸 사용자와 링크 대상 사용자가 동일한 ID인가"라는 신원 바인딩 검사로 교체했다. PortSwigger Authentication 랩의 SSO/OAuth 계열 항목("로그인은 됐지만 누구로 됐는지 확인 안 함")과 정확히 대응하는 사례다.

## 취약점 한 줄 요약
공격자가 알아낸 피해자 이메일이 SAML ACS 콜백 파라미터를 거쳐 `handle_unknown_identity()`에 도달하고, `self.user.is_authenticated`(로그인 여부만 확인)만 통과하면 공격자의 현재 세션에 피해자 계정의 SSO 신원이 연결되어 계정 탈취로 이어진다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 중상. 코드 변경은 조건식 한 줄이지만 "`is_authenticated`(로그인 여부)와 신원 동일성(`user.id` 비교)이 왜 다른 개념인가"를 설명해야 하고, SAML ACS/AuthIdentity 연결 흐름 자체에 대한 배경 설명이 선행되어야 함.
- 재현 환경 구축 부담: 상. Self-hosted Sentry에 여러 조직(멀티테넌트)과 SAML IdP(예: 테스트용 SimpleSAMLphp)를 구성해야 하고, 두 조직 간 계정 탈취 시나리오를 시연하려면 SSO 설정 작업이 상당히 큼. 발표용 데모보다는 코드 리딩 위주로 다루는 편이 현실적.
- nuclei 템플릿 유무 / PoC 공개 여부: `gh api "/search/code?q=CVE-2025-22146+repo:projectdiscovery/nuclei-templates"` 결과 0건, nuclei 템플릿 없음. advisory에 PR 링크만 있고 별도 공개 exploit PoC는 미확인.

## 대안 후보
심각도(critical, CVSS 9.1)와 임팩트(계정 탈취)는 세 후보 중 가장 크고, "인증됨"과 "본인 확인됨"을 혼동한 전형적인 신원 바인딩 결함이라는 점에서 Auth 주제의 핵심 사례로는 가장 적합하다. 다만 SAML·멀티테넌트 개념 설명 부담이 커 초심자 세션 첫 사례로는 무겁고, flask-httpauth(가장 쉬운 진입 사례)로 워밍업한 뒤 심화 사례로 배치하는 편이 낫다. jupyter-scheduler는 diff가 더 짧지만 "게이트 누락"이라는 단순 패턴이라 이 사례가 보여주는 "검증 로직은 있지만 검증 대상이 틀렸다"는 통찰을 대체하지 못한다.
