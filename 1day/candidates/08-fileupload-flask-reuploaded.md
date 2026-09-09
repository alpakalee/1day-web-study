# W8 · 파일 업로드 — Flask-Reuploaded (GHSA-937x-gpqr-72gg)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2026-54567 / 2026-07-17 / High (CVSS 7.5) / Flask-Reuploaded `<= 1.5.0` (1.6.0에서 패치)
- 패치 커밋: jugmac00/flask-reuploaded@5ded76092429c6eb8a4af941b14fbde40a38fff4
- diff 규모: 실질 수정은 `src/flask_uploads/flask_uploads.py` +2/-0 한 줄 삽입뿐. 같은 커밋에 `CHANGES.rst`(+6/-0), `pyproject.toml`(+1/-1), `tests/test_flask_reuploaded.py`(+17/-1)가 포함돼 전체 파일 수는 4개, 합계 +26/-2다. 과제 배경 메모에 있던 "+3/-1 2파일"은 gh api로 재확인한 실측과 달라, 소스 로직만 기준으로 재계산했다.

## 왜 이 주차에 적절한가
- 취약점은 확장자 denylist를 대소문자 처리 비대칭으로 우회하는 구조다. 기본 업로드 경로는 `get_basename()` 내부에서 `lowercase_ext(secure_filename(filename))`을 거쳐 확장자를 소문자로 정규화한 뒤 `extension_allowed()`로 검사한다. 반면 `UploadSet.save(storage, name=...)`로 파일명을 덮어쓰는 경로는 `secure_filename(name)`만 거치고 대소문자를 보존한 채 `extension(basename)`으로 확장자를 뽑아 검사했다 — `"shell.PHP"`가 `extension_allowed("PHP")`를 통과해 denylist(`AllExcept(SCRIPTS)`)를 우회한다.
- PortSwigger 파일 업로드 랩의 "Web shell upload via extension blacklist bypass" 개념과 정확히 대응한다. denylist 방식 자체의 구조적 약점(대소문자·이중 확장자 등 정규화 누락)을 다루는 랩과 같은 결함 클래스이며, 이 케이스는 그중에서도 "정규화 함수가 두 개 존재하는데 한쪽 코드 경로만 그것을 쓴다"는 구체적 원인이 드러나 있어 설명하기 좋다.
- CWE-434(Unrestricted Upload of File with Dangerous Type) + CWE-178(Improper Handling of Case Sensitivity) 조합으로, 이번 주 "확장자 검증"이라는 주제에 정확히 걸린다.

## 취약점 한 줄 요약
`UploadSet.save()`의 `name` 파라미터(입력, 호출자가 지정하는 저장 파일명)가 `secure_filename()`만 거치고 대소문자 보존 상태로 `extension()` → `extension_allowed()` 검사를 통과한 뒤 `storage.save(target)`(싱크)로 디스크에 그대로 기록된다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 매우 쉽다. 실질 수정이 `basename = lowercase_ext(basename)` 한 줄 추가뿐이라, 취약 코드(정규화 누락)와 패치(정규화 함수 호출 삽입)를 나란히 보여주면 5분 안에 원인·수정을 모두 설명할 수 있다. 다만 diff 자체가 너무 짧아 "왜 이 한 줄이 문제였는가"를 이해시키려면 `lowercase_ext()`와 `extension()` 두 헬퍼 함수의 차이, 그리고 기본 경로(`get_basename`)와 override 경로(`save(..., name=)`)가 별개 함수라는 배경 설명을 발표자가 추가로 준비해야 한다.
- 재현 환경 구축 부담: 별도 서버·DB 없이 Flask 앱 하나와 `pip install Flask-Reuploaded==1.5.0`만으로 로컬에서 즉시 재현 가능. advisory에 포함된 PoC 스크립트(`poc_case_fold.py`)가 그대로 동작해 준비 부담이 가장 낮다. 단, 실제 RCE로 이어지려면 대소문자 구분 없는 파일시스템(Windows/macOS)이나 Apache `AddHandler` 설정이 추가로 필요하다.
- nuclei 템플릿 유무 / PoC 공개 여부: `projectdiscovery/nuclei-templates` 코드 검색 결과 CVE-2026-54567 매칭 0건. PoC는 advisory 본문에 `poc_case_fold.py` 전체 소스가 공개돼 있다.

## 대안 후보
kiwitcms 건(GHSA-2fqm-m4r2-fh98 / CVE-2023-33977, +3/-0, 파일 1개)은 validator 함수 하나만 고치는 구조로 diff 크기 면에서 이번 후보보다도 더 작지만, 검증 로직 하나만 보여주면 끝나 "확장자 정규화 비대칭"이라는 이번 주 핵심 개념(정규화 함수가 왜 두 곳에서 다르게 적용됐는가)을 보여줄 여지가 없다. open-webui 업로드→RCE 건(GHSA-ff5c-56m7-vc75 / CVE-2024-8060, +21/-6, 파일 1개)은 업로드가 곧바로 원격 코드 실행으로 이어지는 임팩트를 보여줄 수 있어 매력적이지만, 21줄로 30줄 기준에 근접해 15분 발표에서 diff를 다 소화하기엔 시간이 빠듯하다. Flask-Reuploaded 건은 diff가 극단적으로 짧으면서도 denylist 우회의 원인(대소문자 정규화 함수 분기)이 명확히 드러나 있어, 세 후보 중 개념 전달과 발표 시간 배분의 균형이 가장 좋다고 판단해 채택했다.
