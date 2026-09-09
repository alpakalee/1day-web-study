# W6 · 정보 탐색 — jupyter-server (GHSA-h56g-gq9v-vc8r)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2023-49080 / 2023-12-05 / medium / jupyter-server `< 2.11.2`
- 패치 커밋: https://github.com/jupyter-server/jupyter_server/commit/0056c3aa52cbb28b263a7a609ae5f17618b36652
- diff 규모: `jupyter_server/base/handlers.py` +3/-2, `jupyter_server/services/kernels/handlers.py` +1/-3 (2파일, +4/-5)

## 왜 이 주차에 적절한가
패치 전 `RequestHandler.write_error`(`base/handlers.py`)는 예외 발생 시 `reply["traceback"] = "".join(traceback.format_exception(*exc_info))`로 파이썬 전체 스택 트레이스를 JSON 에러 응답에 그대로 담아 클라이언트에 반환했다. 커널 재시작 API(`services/kernels/handlers.py`)도 동일하게 `traceback = format_tb(e.__traceback__)`를 응답 바디에 실었다. 두 곳 다 서버 파일 시스템 경로가 포함된 파이썬 트레이스백을 사용자에게 노출하는 전형적인 verbose error message 패턴이라, PortSwigger information disclosure 랩의 "에러 메시지를 통한 정보 노출" 절과 정확히 대응한다.

## 취약점 한 줄 요약
API 요청 처리 중 발생한 예외(`exc_info`, `e.__traceback__`)가 별도 필터링 없이 HTTP 에러 응답의 `traceback` JSON 필드(싱크)로 그대로 직렬화되어, 서버 내부 모듈 경로·파일 시스템 구조가 노출된다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 하. 두 핸들러 모두 `traceback.format_exception(...)` / `format_tb(...)` 호출 결과를 빈 문자열 `""`로 치환한 것이 변경의 전부라, "트레이스백 내용을 지웠다"는 의도가 diff만 봐도 바로 읽힌다.
- 재현 환경 구축 부담: 하. `pip install jupyter-server==2.11.1` 후 로컬 실행만으로 취약 버전을 구성할 수 있어 별도 인프라가 필요 없다. 다만 advisory 자체가 "인증 없이 이 에러를 트리거할 알려진 방법이 없다"고 명시해, 실제 트리거 시나리오(커널 재시작 API에 잘못된 파라미터를 보내는 등)를 직접 찾아야 실습이 완성된다.
- nuclei 템플릿 유무 / PoC 공개 여부: `gh api "/search/code?q=CVE-2023-49080+repo:projectdiscovery/nuclei-templates"` 결과 0건. 별도 공개 PoC는 확인 안 함.

## 대안 후보
같은 주차 06-infodisclosure-omero-web(사용자 열거를 통한 정보 노출)과 비교하면, 이쪽은 "스택 트레이스 노출" 자체가 정보 노출인 더 단순하고 고전적인 사례라 입문용으로 적합하다. 다만 advisory가 "공격자가 인증 없이 에러를 유발할 알려진 경로가 없다"고 밝혀 실공격 시나리오는 omero-web(사용자 열거) 쪽이 더 구체적이다.
