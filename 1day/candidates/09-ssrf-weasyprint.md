# W9 · SSRF — weasyprint (GHSA-983w-rhvv-gwmv)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2025-68616 / 2026-01-20 / High / weasyprint `< 68.0`
- 패치 커밋: Kozea/WeasyPrint@b6a14f0f3f4ce9c0c75c1a2d73cb1c5d43f0e565
- diff 규모: 소스 변경은 `weasyprint/urls.py` +5/-2 한 파일. 같은 커밋에 `docs/changelog.rst` +10/-0가 포함돼 전체는 2개 파일이다.

## 왜 이 주차에 적절한가
- WeasyPrint는 HTML을 PDF로 렌더링할 때 `<img src="...">` 등에 적힌 URL을 가져오기 위해 `url_fetcher` 콜백을 호출한다. 개발자가 `allowed_protocols`나 커스텀 `url_fetcher`로 내부 IP·특정 스킴을 막아도, 레거시 `default_url_fetcher`가 내부적으로 `URLFetcher(...).fetch(url)`을 호출할 때 HTTP 리다이렉트를 자동으로 따라가는 `urllib.request.urlopen` 동작을 그대로 물려받고 있었다. 공격자가 검증을 통과하는 외부 URL을 리다이렉트 응답으로 위장해 내부망이나 클라우드 메타데이터 엔드포인트로 최종 요청을 흘려보낼 수 있다.
- 패치는 `URLFetcher(timeout, ssl_context, http_headers, allowed_protocols, allow_redirects=False)`로 명시적 플래그를 추가해 리다이렉트 자동 추적을 끈다. "검증(Check)과 실제 요청(Use) 사이에 리다이렉트라는 제3자 개입 지점이 있으면 TOCTOU가 생긴다"는 이번 주 핵심 개념을 라이브러리 레벨 사례로 보여준다.
- 같은 주차 mobsf 건과 원인 구조(허용 목록 검증 후 리다이렉트로 우회)가 거의 동일해, "이 결함 패턴이 언어·프레임워크를 가리지 않고 반복된다"는 걸 두 사례를 나란히 놓고 설명하기 좋다.

## 취약점 한 줄 요약
사용자가 렌더링을 요청한 HTML 안의 리소스 URL(입력)이 `default_url_fetcher`를 거쳐 `URLFetcher.fetch()`(싱크)로 전달되는데, 이 과정에서 허용 스킴·호스트 검증 이후에 발생하는 HTTP 리다이렉트는 재검증 없이 그대로 따라간다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 쉬움. `allow_redirects=False` 인자 하나를 추가한 게 핵심이라 원인·수정을 한 화면에서 설명할 수 있다. 다만 "왜 `urllib`이 기본적으로 리다이렉트를 따라가는가", "커스텀 `url_fetcher`를 개발자가 넣어도 왜 무력화되는가"라는 배경 설명이 별도로 필요하다.
- 재현 환경 구축 부담: advisory에 실린 PoC 그대로 `victim.py`(내부 서비스 역할, Flask), `attacker.py`(외부에서 302로 내부 주소로 리다이렉트), WeasyPrint로 PDF를 렌더링하는 스크립트 3개만 준비하면 재현 가능해 부담이 낮다.
- nuclei 템플릿 유무 / PoC 공개 여부: `projectdiscovery/nuclei-templates`에서 CVE-2025-68616 검색 결과 0건. advisory 본문에 victim/attacker Flask 앱 전체 소스가 PoC로 공개돼 있다.

## 대안 후보
mobsf 건(GHSA-m435-9v6r-v5f6)은 같은 리다이렉트 우회 패턴이지만 재현하려면 MobSF 전체 스택과 조작된 APK가 필요해 준비 부담이 크다. weasyprint 건은 PoC가 Flask 스크립트 3개로 끝나 준비 시간이 가장 짧고, PDF 렌더링이라는 친숙한 시나리오라 초심자 설명에도 유리해 이번 주 대표 후보로 우선 채택한다.
