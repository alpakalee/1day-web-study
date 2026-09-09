# W8 · 파일 업로드 — open-webui (GHSA-ff5c-56m7-vc75)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2024-8060 / 2025-03-20 / High (CVSS 8.1) / open-webui `< 0.5.17`(advisory 표기, 실제 수정은 아래 참고)
- 패치 커밋: advisory가 링크한 open-webui/open-webui@613a087387c094e71ee91d29c015195ef401e160은 확인 결과 TTS 커스텀 엔드포인트 폴백 로직만 바꾼 무관 커밋이다(diff에 audio.py의 `get_available_models`/`get_available_voices` 폴백 값만 등장, 업로드·파일명 처리 코드는 손대지 않음). `/audio/api/v1/transcriptions`의 `ext = file.filename.split(".")[-1]` 패턴은 v0.5.16은 물론 v0.8.5까지도 그대로 남아 있었고, 실제 방어 코드는 open-webui/open-webui@62ab30f593b1d6f9b2cda0616e49e6ecb7b65703(커밋 메시지 "refac", 2026-03-01)에서 처음 들어갔다. advisory의 first_patched_version(0.5.17)은 신뢰할 수 없다는 뜻이라, 발표 자료에는 advisory 링크 대신 62ab30f를 실제 패치로 제시해야 한다.
- diff 규모: 62ab30f 기준 `backend/open_webui/routers/audio.py` +7/-1 한 파일.

## 왜 이 주차에 적절한가
- 취약 코드는 업로드된 파일의 확장자만 `ext = file.filename.split(".")[-1]`로 뽑아 서버가 생성한 UUID 뒤에 붙이는 구조였다(`filename = f"{id}.{ext}"`). `split(".")`는 파일명 전체에서 마지막 마침표 뒤 문자열을 그대로 가져오므로, 업로드 파일명을 `x.jpg/../../../etc/whatever`처럼 마지막 확장자 뒤에 슬래시와 `..`를 심으면 `ext`에 경로 순회 문자열이 그대로 담기고, 이어지는 `file_path = f"{file_dir}/{filename}"`이 그 경로를 검증 없이 디스크에 `open(file_path, "wb")`로 그대로 써버린다.
- Content-Type 검사(`audio/mpeg`, `audio/wav` 등)는 요청 헤더 값만 보고 통과 여부를 정하는데, 이 값은 클라이언트가 임의로 지정 가능해 실질적 방어가 되지 않는다. "확장자/타입 검증이 있어 보이지만 실제로는 우회 가능한 값에 의존한다"는 이번 주 핵심 개념과 정확히 맞물린다.
- 62ab30f 패치는 `ext.replace("/", "").replace("\\", "").replace("..", "")`로 위험 문자를 제거하고, `os.path.realpath(file_path).startswith(os.path.realpath(file_dir))` 검사를 추가해 방어심층(defense-in-depth)까지 보여준다. 원인(문자열 슬라이싱만으로 확장자 추출)과 대응(문자 제거 + 실제 경로 재검증)이 한 파일 안에 다 들어 있어 설명하기 좋다.

## 취약점 한 줄 요약
`/audio/api/v1/transcriptions`에 첨부된 `file.filename`(입력)이 `split(".")[-1]`로만 가공돼 검증 없이 `file_path`에 조립된 뒤 `open(file_path, "wb")`(싱크)로 서버 디스크에 그대로 기록된다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 쉬움. 다만 advisory가 링크한 커밋이 실제 패치가 아니라는 사실을 먼저 짚어야 하므로, 발표 준비 시간에 "왜 advisory의 커밋 링크를 믿을 수 없었는가"(v0.5.16~v0.8.5 소스를 직접 대조해 확인)를 15초 정도 설명하는 여유가 필요하다.
- 재현 환경 구축 부담: open-webui 공식 Docker 이미지 하나로 컨테이너를 띄우고 인증된 사용자로 멀티파트 업로드 요청 하나만 보내면 재현 가능해 부담이 크지 않다. 다만 실제 RCE급 피해(설정 파일 덮어쓰기 등)를 시연하려면 컨테이너 내부 파일 구조를 사전에 파악해야 해 단순 PoC보다는 준비 시간이 더 든다.
- nuclei 템플릿 유무 / PoC 공개 여부: `projectdiscovery/nuclei-templates`에서 CVE-2024-8060 검색 결과 0건. advisory 본문에는 별도 PoC 코드가 없다.

## 대안 후보
같은 6주차 정보 탐색 후보로 쓰이는 open-webui GHSA-vvxm-vxmr-624h(CVE 미확정, 경로순회를 통한 내부 에러 메시지 정보노출)는 이 건과 코드 경로가 다르다. GHSA-vvxm-vxmr-624h는 2026-03-01 커밋 387225eb(오류 메시지에서 내부 경로 문자열을 숨기는 수정, PR #22108)이 대상이고, 이번 건은 같은 audio.py 파일이지만 업로드 파일명 처리 함수(62ab30f)를 고친 별개 커밋·별개 CVE다. kiwitcms 건(+3/-0)은 diff 크기와 재현 부담 면에서 더 가볍지만, "업로드→임의 파일 쓰기"라는 임팩트를 보여주지 못한다. 이번 주 메인 후보(Flask-Reuploaded)보다 diff가 크고 시간 관리 부담이 있어, 임팩트 중심 보조 후보로 배치하는 편이 적절하다.
