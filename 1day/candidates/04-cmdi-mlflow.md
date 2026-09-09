# W4 · OS Command injection — mlflow (GHSA-rvhj-8chj-8v3c)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2026-0596 / 2026-03-31 / Critical (CVSS 9.6) / mlflow `< 3.9.0` (3.9.0에서 패치)
- 패치 커밋: mlflow/mlflow@202fac4c83ccc8544c087c142b80196d0e60695c
- diff 규모: `mlflow/pyfunc/mlserver.py` +2/-1, 1파일

## 왜 이 주차에 적절한가
- `get_cmd()` 함수의 `cmd = f"mlserver start {model_uri}"`가 취약 코드 전부다. `model_uri`가 이스케이프 없이 셸 명령 문자열에 f-string으로 삽입되고, 이 문자열은 (advisory 설명에 따라) `bash -c`로 실행된다. `model_uri`에 `$()`나 백틱 같은 명령 치환 메타문자를 넣으면 임의 명령이 실행된다. 패치는 `cmd = f"mlserver start {shlex.quote(model_uri)}"`로 단 하나의 변수에 `shlex.quote()`를 씌우는 최소 수정이다.
- PortSwigger가 예시로 드는 "메타문자를 이용한 명령 치환(command substitution)" 공격 형태(`` ` ``, `$()`)와 정확히 일치하고, 수정 방법(`shlex.quote`)도 PortSwigger가 권장하는 표준 방어법 그대로라 "취약 패턴 → 표준 방어" 대응을 가장 깨끗하게 보여준다.
- CVSS 9.6(critical)으로 이번 주차 세 후보 중 임팩트가 가장 크고, 모델 서빙이라는 널리 쓰이는 MLOps 워크플로우에서 나온 최신(2026) 사례라 실전성이 높다.

## 취약점 한 줄 요약
`enable_mlserver=True`로 모델을 서빙할 때 `model_uri`(모델 경로/URI, 낮은 권한 사용자가 쓸 수 있는 디렉토리일 수 있음)가 이스케이프 없이 `get_cmd()`의 `f"mlserver start {model_uri}"`(싱크, `bash -c`로 실행)에 삽입된다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 2줄(`import shlex` 추가 + `shlex.quote()` 적용) 수정. 5개 후보 중 가장 표준적인 수정 패턴이라 "이렇게 고치면 된다"는 결론을 명확히 제시하기 좋다.
- 재현 환경 구축 부담: mlflow 서버 설치 후 `enable_mlserver=True`로 모델을 서빙하는 설정을 별도로 구성해야 하며, mlserver 의존성 설치가 추가로 필요해 세 후보 중 환경 구축이 가장 무겁다. advisory도 "더 높은 권한의 서비스가 낮은 권한 사용자가 쓸 수 있는 디렉토리에서 모델을 서빙하는" 권한 상승 시나리오를 전제로 해 공격 전제조건 설명이 한 단계 더 필요하다.
- nuclei 템플릿 유무 / PoC 공개 여부: `projectdiscovery/nuclei-templates` 코드 검색 결과 CVE-2026-0596 매칭 0건. advisory에 별도 PoC 코드는 없고 취약 원리 설명과 패치 diff만 제공(huntr 바운티 링크 존재).

## 대안 후보
llamafactory(GHSA-hj3w-wrh4-44vp)와 동일한 "f-string + shell 실행" 패턴이지만, mlflow는 (a) 심각도가 critical로 더 높고 (b) 수정법이 `shlex.quote()` 단독으로 이번 주차의 "이스케이프 부재"라는 주제에 가장 교과서적으로 들어맞아 우선 채택했다. 다만 재현 환경 구축 부담이 가장 크므로, 발표에서 실습보다는 코드 리딩 중심으로 다루고 실습은 dcnnt/llamafactory 쪽에 배정하는 편이 안전하다.
