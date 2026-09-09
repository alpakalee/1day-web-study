# W6 · 정보 탐색 — open-webui (GHSA-vvxm-vxmr-624h)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2026-28786 / 2026-03-27 / medium / open-webui `< 0.8.6`
- 패치 커밋: https://github.com/open-webui/open-webui/commit/387225eb8b3906909436004f84fff1b012e067d4
- diff 규모: `backend/open_webui/routers/audio.py` 1파일, +4/-4

## 왜 이 주차에 적절한가
`transcription` 핸들러(`backend/open_webui/routers/audio.py`)는 업로드된 파일의 확장자를 `file.filename.split(".")[-1]`로 뽑아 `{id}.{ext}` 경로를 조립한 뒤 `open()`으로 연다. `filename`을 `os.path.basename()`으로 정규화하지 않고 슬래시만 문자열 치환으로 걷어내던 방식이라 `audio./etc/passwd` 같은 값이 그대로 확장자에 섞여 들어가고, 이때 발생하는 `FileNotFoundError`가 `except` 블록에서 `ERROR_MESSAGES.DEFAULT(e)`로 응답 바디에 그대로 실려 서버의 절대경로(`DATA_DIR`)가 노출된다. "에러 메시지에 담긴 파일 경로로 서버 구조를 추론"하는 이번 주차 주제와 정확히 맞물린다.

## 취약점 한 줄 요약
인증된 일반 사용자가 `POST /api/v1/audio/transcriptions`에 조작된 `filename`을 담아 보내면 그 값이 파일 경로 조립(`file_path = f"{file_dir}/{filename}"`)을 거쳐 `open()` 호출까지 흘러가고, 실패 시 예외 메시지(싱크)에 담긴 서버 절대경로가 HTTP 400 응답으로 그대로 반환된다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 중. 확장자 추출을 `os.path.basename()` 기반으로 바꾸고 두 `except` 블록의 `detail`을 고정 문자열 `"Transcription failed."`로 교체한 4줄 변경이라 코드 자체는 짧지만, "왜 확장자 파싱만 고쳐도 경로 순회가 막히는지"를 이해하려면 `split(".")[-1]`과 `rsplit(".", 1)[-1]`의 차이, `basename()`의 역할을 함께 짚어야 한다.
- 재현 환경 구축 부담: 하. advisory에 공개된 PoC가 `docker run open-webui/open-webui` 한 줄과 회원가입만으로 재현 가능하다고 명시돼 있어 컨테이너 하나로 즉시 실습 가능하다.
- nuclei 템플릿 유무 / PoC 공개 여부: `gh api "/search/code?q=CVE-2026-28786+repo:projectdiscovery/nuclei-templates"` 결과 0건. advisory 본문에 curl 기반 PoC 스크립트가 전문 공개돼 있다.

## 대안 후보
8주차 file upload 후보로 쓰이는 open-webui GHSA-ff5c-56m7-vc75(업로드 파일 처리 결함으로 RCE까지 이어지는 별도 CVE)와는 코드 경로가 다르다. 이쪽은 `audio.py`의 트랜스크립션 업로드 핸들러에서 파일명 파싱 결함으로 정보 노출에 그치고, RCE로 이어지지 않는다는 점에서 6주차 정보 탐색 주제에 더 부합한다.
