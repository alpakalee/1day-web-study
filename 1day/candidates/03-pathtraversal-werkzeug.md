# W3 · File path traversal — Werkzeug (GHSA-f9vj-2wh5-fj8j)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2024-49766 / 2024-10-25 / medium (CVSS4 6.3) / Werkzeug `<= 3.0.5`, 패치 `3.0.6`
- 패치 커밋: https://github.com/pallets/werkzeug/commit/2767bcb10a7dd1c297d812cc5e6d11a474c1f092
- diff 규모: `src/werkzeug/security.py` 1파일, +2/-0 (테스트·CHANGES 별도)

## 왜 이 주차에 적절한가
`safe_join(directory, *pathnames)`는 `filename`이 위험한지 판단할 때 `os.path.isabs(filename)`, `filename == ".."`, `filename.startswith("../")`만 검사하고 안전하면 `posixpath.join`으로 이어붙인다. Windows + Python 3.11 미만에서는 `os.path.isabs`가 내부적으로 `ntpath.isabs`를 쓰는데, 이 함수가 드라이브 문자 없는 절대경로(`/etc/passwd`, `/foo`처럼 슬래시로 시작하지만 `C:` 같은 드라이브가 없는 경로)를 절대경로로 인식하지 못한다. 그래서 `filename="/etc/passwd"`가 `isabs()` 체크를 그대로 통과해 `safe_join`이 이를 상대경로로 오판하고 반환값을 만들어 준다. PortSwigger 랩들이 "필터를 우회해 `..`를 통과시키는" 데 집중하는 반면, 이 사례는 애플리케이션 코드가 아니라 프레임워크가 제공하는 표준 방어 함수(`safe_join`) 자체의 플랫폼별 결함이라, "라이브러리를 믿고 썼는데도 뚫리는 경우가 있다"는 걸 보여주는 대표 사례로 적합하다.

## 취약점 한 줄 요약
`safe_join()`에 전달된 사용자 제어 경로 조각(`filename`, 예: 업로드/다운로드 API의 파일명 파라미터)이 Windows·Python<3.11 환경에서 `ntpath.isabs()`의 드라이브 미인식 결함 때문에 절대경로 판별을 통과해, 지정된 디렉토리 밖 임의 경로로 `join`된 결과가 그대로 반환된다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 하. 패치는 `filename.startswith("/")` 조건 한 줄 추가뿐이고, 커밋 메시지에 "ntpath.isabs doesn't catch this on Python < 3.11"이라고 원인이 명시돼 있어 짧고 명확하다. 다만 "왜 `/foo`가 Windows에서 절대경로가 아닌 걸로 판정되는지"(드라이브 레터 유무 기준)는 별도 설명이 필요하다.
- 재현 환경 구축 부담: 중. Windows + Python 3.10 이하 조합이 있어야 재현되므로(3.11+에서는 `ntpath.isabs`가 수정돼 있어 재현 안 됨), 스터디 참가자 환경이 대부분 Python 3.11+/최신 리눅스면 실습에서 직접 재현하기 까다롭다. `python -c "import ntpath; print(ntpath.isabs('/x'))"`로 버전별 동작 차이만 보여주는 미니 데모는 쉽다.
- nuclei 템플릿 유무 / PoC 공개 여부: `gh api "/search/code?q=CVE-2024-49766+repo:projectdiscovery/nuclei-templates"` 결과 0건. 공개 익스플로잇 코드는 확인하지 않음(advisory 설명만으로 원리가 자명해 별도 PoC 없이도 이해 가능).

## 대안 후보
같은 3주차 후보인 keras(symlink 우회)·GitPython(검증 누락)과 비교하면, werkzeug 건은 유일하게 "방어 코드는 있었지만 플랫폼 의존적 표준 라이브러리 함수의 버그로 뚫린" 유형이라 세 후보 중 방어책 설계의 한계를 가장 잘 보여준다. 다만 Windows+구버전 Python이라는 재현 조건이 특수해 실습 난이도는 GitPython보다 높고, keras의 symlink 트릭보다는 원리가 단순하다. 발표 순서상 "naive한 미검증(GitPython) → 표준 함수의 결함(werkzeug) → 방어 로직의 허점(keras symlink)"으로 난이도를 올려가는 구성에 werkzeug를 중간에 배치하면 좋다.
