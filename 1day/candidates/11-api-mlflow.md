# W11 · API test — Broken Authentication — mlflow (GHSA-8c7q-86fq-vvmh)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2026-2651 / 2026-05-26 / critical (CVSS 3.0 9.0) / mlflow (pip) `< 3.11.0rc0`, first_patched_version 3.11.0rc1
- 패치 커밋: https://github.com/mlflow/mlflow/commit/d7290811d8f3c95366d80109424edc1fb1ad966f
- diff 규모: +3/-0, 1파일 (`mlflow/server/auth/__init__.py`, 실제 로직 변경분. 테스트 파일 `tests/server/auth/test_auth.py` +41/-0는 별도)

## 왜 이 주차에 적절한가
`--serve-artifacts` 모드의 인가 계층이 `_is_proxy_artifact_path()`로 "이 경로가 아티팩트 프록시 경로인지"를 판별하고, 맞으면 `_get_proxy_artifact_validator()`로 HTTP 메서드별 권한 검증 함수를 매핑해 실행한다. 패치 전에는 이 두 함수 모두 멀티파트 업로드(MPU) 경로 `mlflow-artifacts/mpu/*`를 아예 몰랐다 — `prefixes` 리스트에 `mpu/` 항목이 없고, 메서드-검증자 매핑 딕셔너리에 `POST` 키가 없어 `_get_proxy_artifact_validator("POST", ...)`가 `None`을 반환했다. 즉 엔드포인트 자체가 인가 검사 대상 목록에서 누락되어 있던 것으로, "권한 체크 함수는 있지만 특정 라우트가 그 체크의 사정거리 밖에 있다"는 API 테스트 주제의 핵심 함정을 그대로 보여준다.

## 취약점 한 줄 요약
`POST /mlflow-artifacts/mpu/{action}/{experiment_id}/artifacts/...` 요청의 `experiment_id`·`artifact_path`가 인가 검증을 거치지 않고 바로 멀티파트 업로드 싱크(S3/스토리지 백엔드로의 파트 생성·완료)에 도달해, 다른 사용자의 실험에 속한 아티팩트를 임의로 덮어쓸 수 있다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 매우 낮음. `prefixes` 리스트에 두 줄, 메서드 매핑 딕셔너리에 한 줄 추가하는 것으로 끝나 "어떤 경로가 검증 대상에서 빠졌는가"를 diff만 보고 바로 알 수 있다. 다만 "왜 GET/PUT/DELETE는 이미 매핑돼 있었는데 새로 생긴 POST(MPU)만 빠졌는가"는 별도 설명 필요 — 신규 기능 추가 시 인가 매핑 갱신을 빠뜨린 전형적 패턴.
- 재현 환경 구축 부담: mlflow는 `pip install mlflow`로 설치해 `mlflow server --serve-artifacts` 한 줄로 로컬 구동 가능. 5주차 command injection 후보로 이미 mlflow(GHSA-rvhj-8chj-8v3c, `shell=True` 명령 조립)가 쓰였다면 같은 저장소라 환경 구축을 재사용할 수 있어 부담이 낮다.
- nuclei 템플릿 유무 / PoC 공개 여부: nuclei-templates 검색 결과 0건. huntr 바운티 링크(huntr.com/bounties/65beb119-...)에 상세 리포트가 있을 가능성이 높으나 이 세션에서는 advisory 텍스트 이상의 별도 PoC 스크립트는 확인하지 못함(미확인).

## 대안 후보
- GHSA-g8gc-6c4h-jg86 (wger, CVE-2026-27839, medium): 이미 이번 주 대표 후보로 채택됨(`11-api-wger.md`). wger는 인증된 사용자 간 객체 소유권 검증 누락(BOLA)이고, 이 mlflow 건은 엔드포인트 자체가 인가 매핑에서 누락된 인증/인가 부재(broken authentication에 더 가까움)라 결함 성격이 다르다.
- GHSA-x287-5c68-36wp (openwisp-ipam, medium, CVE 미부여): advisory가 "broken object-level authorization"을 자체 정의해주는 교재형 사례이나 CVE가 없어 스캐너·위협 인텔 연계 설명이 어렵다.
- 참고: 4주차 command injection 후보로 검토된 다른 mlflow CVE(GHSA-rvhj-8chj-8v3c, `subprocess.run(..., shell=True)` 기반 명령 조립)와는 CWE(command injection vs missing authorization)와 코드 위치(모델 실행 경로 vs 아티팩트 인증 계층)가 완전히 다른 별개 취약점이다. 같은 프로젝트에서 서로 다른 두 주차 교재를 뽑는 셈이므로 발표 시 CVE 번호와 파일 경로를 명확히 구분해서 소개해야 한다.
