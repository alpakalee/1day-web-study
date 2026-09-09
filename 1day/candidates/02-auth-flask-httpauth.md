# W2 · Authentication — Flask-HTTPAuth (GHSA-p44q-vqpr-4xmg)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2026-34531 / 2026-03-31 / medium (CVSS3 6.5) / Flask-HTTPAuth `<= 4.8.0`, 패치 `4.8.1`
- 패치 커밋: https://github.com/miguelgrinberg/flask-httpauth/commit/b15ffe9e50e110d7174ccd944f642079e1dcf9ee
- diff 규모: `flask_httpauth.py` +2/-2, 테스트 파일 포함 총 2파일 (핵심 로직은 1파일 +2/-2)

## 왜 이 주차에 적절한가
`HTTPTokenAuth.authenticate()`는 클라이언트가 보낸 토큰을 `token = getattr(auth, 'token', '')`로 꺼낸다. `Authorization` 헤더가 아예 없거나 스킴만 있고 토큰이 비어 있으면 `auth.token` 속성 자체가 없어 `getattr`의 기본값인 빈 문자열 `''`이 그대로 `token`이 된다. 이어서 `if self.verify_token_callback:` 조건만 확인하고 `token`이 실제로 값을 가졌는지는 검사하지 않은 채 `verify_token_callback('')`을 호출한다. 즉 "인증 정보 없음"과 "빈 문자열이라는 유효한 인증 정보"를 구분하지 못하는 결함으로, 애플리케이션이 토큰 미설정 사용자를 DB에 빈 문자열로 저장해두면(NULL이 아니라) 토큰 없이 보낸 요청이 그 사용자로 인증되어 버린다. 인증 콜백에 "빈 값도 검증을 통과할 자격이 있는 입력"으로 흘러들어가는, 미들웨어 계층의 미묘한 인증 우회 사례다.

## 취약점 한 줄 요약
`Authorization` 헤더에서 토큰이 누락된 요청이 `authenticate()`의 `getattr(auth, 'token', '')` 기본값을 거쳐 빈 문자열로 `verify_token_callback`(애플리케이션이 등록한 사용자 조회 함수)에 그대로 전달된다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 하. 로직 변경이 `''` → `None` 기본값 교체와 `if token and ...` 가드 추가 두 줄뿐이라 "왜 빈 문자열이 위험한 입력인지"만 짚어주면 바로 이해된다.
- 재현 환경 구축 부담: 하. Flask + Flask-HTTPAuth로 `verify_token` 콜백을 등록하고, DB(또는 딕셔너리)에 토큰 미설정 사용자를 빈 문자열로 저장한 뒤 `Authorization` 헤더 없이 요청만 보내면 재현된다. 별도 인프라 불필요.
- nuclei 템플릿 유무 / PoC 공개 여부: `gh api "/search/code?q=CVE-2026-34531+repo:projectdiscovery/nuclei-templates"` 결과 0건, nuclei 템플릿 없음. 별도 공개 PoC 미확인.

## 대안 후보
같은 2주차 후보인 jupyter-scheduler(CWE-287+200, 데코레이터 누락)와 sentry(CWE-287, SSO 신원 바인딩 누락) 대비, 이 케이스는 유일하게 "라이브러리가 애플리케이션에 콜백을 넘겨주는 경계"에서 발생하는 문제라 인증 프레임워크 설계 자체를 다룬다. 다만 실질적 악용 조건(토큰 없는 사용자를 빈 문자열로 저장)이 애플리케이션 구현에 달려 있어 심각도·임팩트는 셋 중 가장 제한적이다. 난이도는 셋 중 가장 낮아 입문 세션 첫 사례로 적합하고, sentry는 임팩트가 가장 크지만(critical, 계정 탈취) SAML 개념 설명이 선행되어야 해 진입장벽이 있다. jupyter-scheduler는 diff가 1줄로 가장 짧지만 "데코레이터 누락"이라는 패턴이 authenticate() 로직 자체를 보여주지 못해 교육적 깊이는 이 후보보다 얕다.
