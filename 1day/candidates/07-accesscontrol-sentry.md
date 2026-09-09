# W7 · 접근 제어 — sentry (GHSA-4xqm-4p72-87h6)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2023-36829 / 2023-07-06 / medium / sentry (getsentry/sentry) `>= 23.6.0, < 23.6.2`
- 패치 커밋: https://github.com/getsentry/sentry/commit/19248fb9802c252665b802aeab02fdc65ed47dc9
- diff 규모: `src/sentry/api/base.py` 1파일, +1/-1

## 왜 이 주차에 적절한가
`allow_cors_options_wrapper`(`src/sentry/api/base.py`)는 요청의 `Origin` 헤더가 `system.base-hostname` 설정값으로 끝나기만 하면(`origin.endswith(basehost)`) `Access-Control-Allow-Credentials: true`를 응답에 실었다. 이 단순 접미사 비교는 `basehost`가 `example.com`일 때 `evil-example.com`도 통과시켜, 신뢰 도메인 경계를 우회한 임의 오리진이 자격 증명 포함 CORS 응답을 받게 한다. Burp로 `Origin` 헤더 값을 바꿔가며 응답 헤더 변화를 관찰하는 실습과 바로 연결되는, 접근 제어 주차의 대표적인 CORS 오정책 사례다.

## 취약점 한 줄 요약
클라이언트가 보낸 `Origin` 요청 헤더 값이 `origin.endswith(basehost)` 검증(싱크)을 거쳐 `Access-Control-Allow-Credentials` 응답 헤더 설정 여부를 결정하기 때문에, `basehost`를 접미사로만 포함하는 임의 도메인도 자격 증명 허용을 받아낼 수 있다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 하. 핵심 수정은 `origin.endswith(basehost)`를 `origin.endswith(("://" + basehost, "." + basehost))`로 바꾼 한 줄뿐이라, "접미사 비교가 왜 위험한가"를 한 줄 대조로 바로 설명할 수 있다.
- 재현 환경 구축 부담: 중. `system.base-hostname`을 명시적으로 설정한 자체 호스팅 Sentry 인스턴스가 있어야 재현되며, SaaS 버전은 영향받지 않는다. self-hosted 도커 컴포즈로 옵션을 설정해 띄우는 준비가 필요하다.
- nuclei 템플릿 유무 / PoC 공개 여부: `gh api "/search/code?q=CVE-2023-36829+repo:projectdiscovery/nuclei-templates"` 결과 0건. 별도 공개 PoC는 확인 안 함. advisory에 패치 PR(getsentry/sentry#52276) 링크가 공개돼 있어 diff 확인은 용이하다.

## 대안 후보
2주차 Auth 후보로 쓰이는 sentry GHSA-7pq6-v88g-wf3w와는 결함 유형이 다르다. 그쪽은 SAML 신원 바인딩 검증 누락으로 인증 우회이고, 이번 건은 CORS 오리진 문자열 비교 로직 결함으로 접근 제어 범주다. 같은 패키지의 다른 코드 경로이므로 두 주차에서 각각 다뤄도 중복되지 않는다.
