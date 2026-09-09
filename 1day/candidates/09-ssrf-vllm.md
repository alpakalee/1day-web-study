# W9 · SSRF — vllm (GHSA-v359-jj2v-j536)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2026-25960 / 2026-03-09 / Medium (기존 GHSA-qh4c-xf7m-gxfc SSRF 수정에 대한 우회) / vllm `>= 0.15.1, < 0.17.0`
- 패치 커밋: vllm-project/vllm@6f3b2047abd4a748e3db4a68543f8221358002c0 (PR #34743)
- diff 규모: 소스 변경은 `vllm/multimodal/media/connector.py` +2/-2 한 파일. 같은 커밋에 회귀 테스트 `tests/multimodal/media/test_connector.py` +57/-0가 함께 포함돼 전체는 2개 파일이다.

## 왜 이 주차에 적절한가
- vllm은 이전 SSRF 신고(GHSA-qh4c-xf7m-gxfc)에 대응해 `urllib3.util.parse_url()`로 사용자가 준 이미지/비디오 URL의 호스트를 추출해 허용 도메인 목록과 대조하는 검증 로직(`url_spec`)을 도입했다. 그런데 실제 HTTP 요청은 `aiohttp`(내부적으로 `yarl` 파서 사용)로 나가는데, `\`(백슬래시) 문자를 두 파서가 다르게 해석한다. `urllib3`는 `\`를 경로의 일부로 URL 인코딩하지만 `yarl`은 `\`를 userinfo 구분자로 해석해 `@` 뒤를 실제 호스트로 취급한다. 그 결과 `https://httpbin.org\@evil.com/` 같은 URL은 검증 단계에서 호스트 `httpbin.org`로 통과하지만, 실제 요청은 `evil.com`으로 나간다.
- `load_from_url`/`load_from_url_async`는 검증을 거친 `url_spec.url`이 아니라 검증 전 원본 변수 `url`을 그대로 `connection.get_bytes(url, ...)`/`connection.async_get_bytes(url, ...)`에 넘기고 있었다. 패치는 이 두 호출의 인자를 `url_spec.url`로 바꾸는 것뿐이다. "검증 함수가 반환한 정규화된 값을 쓰지 않고 원본 입력을 그대로 싱크에 넘기는" 전형적인 TOCTOU/파서 불일치형 SSRF로, 검증 로직 자체는 멀쩡한데 호출부 변수 선택 실수로 뚫린 사례라 이번 주 다른 두 후보(리다이렉트 우회)와 다른 각도를 보여준다.
- CWE-918(SSRF)이면서 동시에 "서로 다른 파서 간 URL 해석 불일치"라는 좀 더 미묘한 결함 클래스를 다뤄, 세 후보 중 가장 개념적으로 도전적인 사례다.

## 취약점 한 줄 요약
사용자가 지정한 이미지/비디오 URL(입력)이 `urllib3.parse_url()` 기반 허용 도메인 검증을 통과한 뒤, 검증된 `url_spec.url`이 아니라 원본 `url` 변수가 `aiohttp` 기반 `connection.get_bytes()`/`async_get_bytes()`(싱크)로 전달돼 실제 요청 시 다른 호스트로 해석될 수 있다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 코드 수정 자체(`url` → `url_spec.url` 두 줄)는 매우 쉽지만, "왜 두 값이 다를 수 있는가"를 이해하려면 `urllib3`와 `yarl`의 URL 파싱 차이(백슬래시 처리)를 별도로 설명해야 해 순수 diff 난이도보다 개념 설명 부담이 크다. 초심자에게는 "검증 함수의 반환값을 실제로 쓰고 있는지 항상 확인하라"는 교훈으로 단순화해서 전달하는 편이 낫다.
- 재현 환경 구축 부담: vllm은 GPU 추론 서버로 무거워서, 로컬에서 멀티모달 서버 전체를 띄우기보다는 advisory에 포함된 회귀 테스트(`test_ssrf_bypass_backslash_in_url`)를 pytest로 실행하는 방식이 현실적이다. 발표 시연으로는 `MediaConnector` 단위로 코드 조각만 잘라내 스크립트로 보여주는 편이 부담이 적다.
- nuclei 템플릿 유무 / PoC 공개 여부: `projectdiscovery/nuclei-templates`에서 CVE-2026-25960 검색 결과 0건. 별도 PoC 스크립트 공개는 없지만, 패치 커밋에 포함된 pytest 테스트 코드가 그대로 공격 페이로드(`http://127.0.0.1:{port}\@example.com/...`)와 기대 동작을 보여준다.

## 대안 후보
mobsf·weasyprint 두 건은 모두 "검증 후 리다이렉트로 우회"라는 같은 패턴이라 나란히 배치하면 개념이 겹친다. vllm 건은 리다이렉트가 아니라 파서 불일치라는 별도 우회 기법을 보여줘 이번 주 세 후보에 다양성을 더하지만, GPU 인프라가 필요한 무거운 프로젝트라 실제 서버를 띄우는 시연보다는 코드 리딩 위주로 발표를 구성해야 한다는 제약이 있다.
