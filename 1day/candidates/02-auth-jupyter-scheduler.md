# W2 · Authentication — jupyter-scheduler (GHSA-v9g2-g7j4-4jxc)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2024-28188 / 2024-05-23 / medium (CVSS3 5.3) / jupyter-scheduler `>=1.0.0,<1.1.6`, `==1.2.0`, `>=1.3.0,<1.8.2`, `>=2.0.0,<2.5.2`
- 패치 커밋: https://github.com/jupyter-server/jupyter-scheduler/commit/06435a2277bb2b8f441ec9cedafa474572b92c5d
- diff 규모: 핸들러 파일 1파일 +1/-0 (동일 패치가 버전 브랜치별로 4개 커밋에 반복 적용됨)

## 왜 이 주차에 적절한가
`RuntimeEnvironmentsHandler(ExtensionHandlerMixin, JobHandlersMixin, APIHandler)`의 `get()` 메서드에는 같은 파일의 다른 핸들러들과 달리 `@authenticated` 데코레이터가 빠져 있었다. Jupyter Server의 인증 체계는 각 `APIHandler` 서브클래스 메서드에 이 데코레이터를 붙이는 방식으로 세션/토큰 검사를 강제하는데, 이 한 줄이 누락되면 Tornado 라우팅 단계에서 인증 검사 자체가 스킵되어 로그인 여부와 무관하게 엔드포인트가 열린다. `verify_token`처럼 "검증 로직이 틀렸다"가 아니라 "검증 로직 호출 자체가 빠졌다"는 점에서, 같은 주차 flask-httpauth·sentry 사례(콜백/조건식이 틀린 인증 로직 결함)와 대비되는 "인증 게이트 자체를 안 씌운" 패턴이다.

## 취약점 한 줄 요약
`GET /scheduler/runtime_environments` 요청이 `@authenticated` 누락으로 인증 검사를 거치지 않고 곧바로 `get()` 핸들러에 도달해, 서버에 설치된 Conda 환경 이름 목록을 미인증 사용자에게 반환한다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 최하. 데코레이터 한 줄 추가가 전부라 "이 줄이 무엇을 검사하는가"만 설명하면 5분 내 이해 가능. 다만 diff가 너무 짧아 별도 설명 없이는 "왜 이게 취약점인가"가 와닿지 않을 수 있음.
- 재현 환경 구축 부담: 중. `jupyter_server` + 취약 버전 `jupyter-scheduler` 확장을 설치하고 서버를 인증 없이(또는 토큰 있는 상태에서 별도 세션으로) 띄워야 하며, Jupyter 자체의 인증 모델(토큰 URL, XSRF 등)을 먼저 이해해야 정확히 재현된다. 순수 Flask/Django 예제보다 스캐폴딩이 무겁다.
- nuclei 템플릿 유무 / PoC 공개 여부: `gh api "/search/code?q=CVE-2024-28188+repo:projectdiscovery/nuclei-templates"` 결과 0건, nuclei 템플릿 없음. advisory 외 별도 공개 PoC 미확인.

## 대안 후보
flask-httpauth(콜백에 빈 토큰이 흘러들어가는 로직 결함)와 sentry(신원 바인딩 조건식 결함)는 둘 다 "인증 로직이 실행은 되지만 판단이 틀렸다"는 유형인 반면, 이 사례는 "인증 로직 자체가 호출되지 않았다"는 가장 원초적인 CWE-287 패턴이라 세 후보를 나란히 놓으면 인증 결함의 스펙트럼(게이트 누락 → 콜백 오검증 → 신원 바인딩 누락)을 보여줄 수 있다. 다만 diff가 1줄뿐이라 단독으로는 논의거리가 부족하고, 노출 정보도 Conda 환경 이름 정도로 임팩트가 낮아(CVSS 5.3) 세 후보 중 가장 약한 사례에 가깝다. Jupyter 인증 모델 설명 부담까지 고려하면 발표 우선순위는 flask-httpauth보다 낮다.
