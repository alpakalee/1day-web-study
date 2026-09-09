# W3 · File path traversal — keras (GHSA-58hv-7753-xmfq)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2026-12482 / 2026-07-14 / low (CVSS3 3.1) / keras `< 3.12.3`, `>= 3.13.0 < 3.15.0`
- 패치 커밋: https://github.com/keras-team/keras/commit/9867df45c456dd1077a6243bb56219f66e288150 (PR #23015)
- diff 규모: `keras/src/utils/file_utils.py` 1파일, +1/-1

## 왜 이 주차에 적절한가
`keras.utils.get_file(extract=True)`는 tar 압축 해제 시 각 멤버 경로를 `resolve_sub_path` → `resolve_path`로 정규화해 추출 디렉토리 안에 있는지 검사한다. 패치 전 `resolve_path`는 `os.path.realpath(os.path.abspath(path))`였는데, `abspath`가 먼저 `..`를 텍스트 상으로(심볼릭 링크를 따라가기 전에) 지워버린다. 그래서 tar 멤버 이름이 `link/../ESCAPED`이고 `link`가 추출 디렉토리 내부를 가리키는 심볼릭 링크(`link -> .`)일 때, `abspath`가 `link/..`를 문자열 그대로 상쇄시켜 `realpath`가 심볼릭 링크를 전혀 거치지 않게 되고, 검사 결과는 "안전"으로 판정되지만 `tarfile.extractall`은 실제로는 심볼릭 링크를 따라가 추출 디렉토리 바깥에 파일을 쓴다. `abspath`(텍스트 정규화)와 `realpath`(심볼릭 링크 해석)의 순서 차이가 만드는 TOCTOU급 우회로, PortSwigger 자료에서 잘 다루지 않는 "정규화 함수를 두 번 겹쳐 썼다가 순서 때문에 뚫리는" 패턴을 보여준다.

## 취약점 한 줄 요약
사용자가 업로드하거나 원격에서 내려받은 tar 아카이브 안의 심볼릭 링크 멤버(`link -> .`)와 그 아래 `..`를 포함한 경로(`link/../escaped.txt`)가 `resolve_path()`의 `abspath`+`realpath` 순서 문제 때문에 안전 검사를 통과해, `tarfile.extractall`이 추출 디렉토리 밖에 파일을 쓰게 된다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 중상. 코드 변경은 `os.path.realpath(os.path.abspath(path))`를 `os.path.realpath(path)`로 바꾸는 한 줄이지만, `abspath`(순수 문자열 조작)와 `realpath`(파일시스템 조회 및 심볼릭 링크 해석)의 의미 차이와 적용 순서가 결과를 왜 바꾸는지 이해하려면 별도 설명이 필요하다.
- 재현 환경 구축 부담: 중. 심볼릭 링크를 담은 tar를 파이썬 `tarfile` 모듈로 직접 만들어야 하고(`TarInfo(type=SYMTYPE)`), keras가 설치된 로컬 파이썬 환경에서 `get_file(extract=True)`를 호출해 추출 디렉토리 상위에 파일이 생기는지 확인하는 방식이라 웹 요청 기반 실습보다는 스크립트 실습에 가깝다. PR 본문에 최소 재현 스크립트가 그대로 공개돼 있어 그대로 옮기면 된다.
- nuclei 템플릿 유무 / PoC 공개 여부: `gh api "/search/code?q=CVE-2026-12482+repo:projectdiscovery/nuclei-templates"` 결과 0건. PR #23015 본문에 재현 스크립트가 공개돼 있어 별도 PoC 탐색 없이 그대로 활용 가능.

## 대안 후보
werkzeug(표준 함수의 플랫폼 의존 버그), GitPython(검증 자체 부재)과 비교하면 keras 건은 "검증 로직은 있고 실행도 됐지만 정규화 함수 두 개의 적용 순서가 틀려 우회되는" 가장 미묘한 유형이다. 세 후보 중 코드 변경량은 가장 작지만 개념적으로는 가장 어렵고, 웹 요청만으로 재현되지 않아 이번 스터디에서 다루는 "웹 해킹" 맥락과의 직접 연결(HTTP 입력→싱크)이 약하다는 점이 단점이다. 웹 입력 경로가 명확한 사례를 우선한다면 werkzeug나 GitPython을 대표로, keras는 보너스 심화 사례로 배치하는 편이 낫다.
