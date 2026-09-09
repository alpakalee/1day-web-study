# W3 · File path traversal — GitPython (GHSA-cwvm-v4w8-q58c)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2023-41040 / 2023-08-30 / medium (CVSS3 4.0) / GitPython `< 3.1.37`, 패치 `3.1.37`
- 패치 커밋: https://github.com/gitpython-developers/GitPython/commit/74e55ee4544867e1bd976b7df5a45869ee397b0b
- diff 규모: `git/refs/symbolic.py` 1파일, +2/-0

## 왜 이 주차에 적절한가
`git/refs/symbolic.py`의 `_get_ref_info_helper(repo, ref_path, ...)`는 심볼릭 참조를 읽을 때 `ref_path`를 저장소 루트 디렉토리와 그대로 결합해 파일을 연다. 패치 전에는 `ref_path`에 `..`가 포함돼 있는지 전혀 검사하지 않았다. `repo.commit("../README.md")`, `repo.tree("../README.md")`, `repo.index.diff("../README.md")`처럼 `..`를 넣은 참조 이름을 넘기면 `.git` 디렉토리 밖의 파일을 읽어 그 내용을 커밋 SHA인 것처럼 해석을 시도한다. 방어 코드가 아예 없었다는 점에서 이번 주차 다른 후보인 werkzeug(표준 함수의 결함), keras(정규화 순서 문제)와 달리 가장 단순한 "검증 누락형" traversal이라 첫 사례로 다루기 좋다.

## 취약점 한 줄 요약
`Repo.commit()`, `Repo.tree()`, `IndexFile.diff()` 등에 전달되는 참조 이름 문자열(`ref_path`)이 `_get_ref_info_helper()`에서 `..` 포함 여부 검증 없이 저장소 디렉토리 경로와 결합돼, `.git` 밖 임의 파일을 읽어보는 blind file read(파일 존재/내용 유무를 간접 관찰 가능한 수준)로 이어진다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 하. 패치는 함수 시작부에 `if ".." in str(ref_path): raise ValueError(...)` 두 줄을 추가한 것이 전부라, "왜 이렇게만 해도 막히는지"와 "왜 이전엔 이 체크가 없었는지"를 바로 이해할 수 있다.
- 재현 환경 구축 부담: 하. advisory에 그대로 실린 PoC가 `git.Repo(".")`와 `r.commit("../README.md")` 세 줄뿐이라, 아무 로컬 git 저장소에서 GitPython만 설치하면 바로 재현된다. 다만 응답이 파일 내용을 직접 반환하지 않고 "이 참조가 유효한 커밋으로 해석되는지" 여부로만 판단 가능한 blind 특성이 있어, 완전한 파일 읽기 시연보다는 존재 여부 오라클 시연에 가깝다.
- nuclei 템플릿 유무 / PoC 공개 여부: `gh api "/search/code?q=CVE-2023-41040+repo:projectdiscovery/nuclei-templates"` 결과 0건. advisory 자체에 재현 PoC가 공개돼 있어 별도 탐색 불필요.

## 대안 후보
werkzeug(표준 함수의 플랫폼별 버그), keras(정규화 함수 두 개의 적용 순서 문제)와 나란히 놓으면 GitPython 건이 코드량·개념 난이도 모두 가장 낮아 3주차 도입부 사례로 적합하다. 다만 결과가 blind이고 CVSS도 낮아(4.0) "임팩트가 크다"는 인상을 주기는 약하므로, 발표 순서를 GitPython(개념 도입) → werkzeug(표준 함수도 뚫린다) → keras(정규화 순서라는 심화 개념)로 구성하는 편을 권한다.
