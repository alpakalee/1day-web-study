# W7 · 접근 제어 — changedetection.io (GHSA-hcvp-2cc7-jrwr)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2024-23329 / 2024-01-23 / low / changedetection.io `>= 0.39.14, <= 0.45.12`
- 패치 커밋: https://github.com/dgtlmoon/changedetection.io/commit/402f1e47e78ecd155b1e90f30cce424ff7763e0f
- diff 규모: `changedetectionio/api/api_v1.py` 1파일, +1/-0

## 왜 이 주차에 적절한가
`WatchHistory` 리소스의 `get(self, uuid)` 핸들러(`changedetectionio/api/api_v1.py`)는 같은 파일의 다른 API 엔드포인트들과 달리 `@auth.check_token` 데코레이터가 붙어 있지 않았다. 그 결과 `x-api-key` 헤더 없이도 `/api/v1/watch/<uuid>/history`를 호출할 수 있었다. 데코레이터 하나의 유무가 인증 여부를 가르는 구조라, PortSwigger access control 랩의 "보호되지 않은 기능(unprotected functionality)" 패턴을 코드 레벨에서 그대로 보여준다.

## 취약점 한 줄 요약
`WatchHistory.get`이 인증 데코레이터 없이 `uuid` 경로 파라미터만으로 워치 히스토리(스냅샷 경로 목록)를 반환하는 싱크까지 도달해, watch UUID만 알면 누구나 무인증으로 조회할 수 있다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 하. 함수 정의 바로 위에 `@auth.check_token` 한 줄을 추가한 것이 패치 전부라, "데코레이터가 빠지면 인증이 걸리지 않는다"는 개념을 가장 적은 코드로 보여줄 수 있다.
- 재현 환경 구축 부담: 하. changedetection.io는 단일 Flask 앱으로 `pip install` 또는 공식 도커 이미지로 바로 띄울 수 있고, advisory에 공개된 curl PoC 두 줄로 바로 재현된다.
- nuclei 템플릿 유무 / PoC 공개 여부: `gh api "/search/code?q=CVE-2024-23329+repo:projectdiscovery/nuclei-templates"` 결과 0건. advisory 본문에 curl 기반 PoC가 전문 공개돼 있다.

## 대안 후보
같은 주차 ethyca-fides(RBAC 스코프 오정의), sentry(CORS 오리진 검증 결함) 후보와 비교하면 이쪽이 가장 단순한 결함 유형이다. 데코레이터 누락 자체가 원인이라 "인가 체크가 어디서 빠지는가"를 보여주는 도입부 사례로 적합하고, 나머지 둘은 각각 권한 스코프 목록 오타와 문자열 비교 로직 결함으로 한 단계 더 깊은 코드 분석이 필요하다.
