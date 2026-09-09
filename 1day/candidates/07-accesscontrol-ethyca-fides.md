# W7 · 접근 제어 — ethyca-fides (GHSA-rjxg-rpg3-9r89)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2023-46125 / 2023-10-24 / medium / ethyca-fides `< 2.22.1`
- 패치 커밋: https://github.com/ethyca/fides/commit/c9f3a620a4b4c1916e0941cb5624dcd636f06d06
- diff 규모: `src/fides/api/oauth/roles.py` 1파일, +1/-1

## 왜 이 주차에 적절한가
`roles.py`의 `viewer_scopes` 리스트에 `CONFIG_READ`가 포함돼 있어, 가장 낮은 권한인 `viewer` 역할 사용자도 `GET api/v1/config` 엔드포인트로 서버 설정(백엔드 주소·포트·DB 사용자명 등)을 조회할 수 있었다. 역할별 허용 스코프 목록에 상위 권한 스코프가 잘못 섞여 들어간 전형적인 RBAC 설정 오류로, PortSwigger access control 랩의 "역할 기반 접근 제어 결함" 절과 정확히 대응한다.

## 취약점 한 줄 요약
저권한 `viewer`/`contributor` 계정의 JWT가 스코프 검증을 거칠 때 `viewer_scopes`/`contributor_scopes` 목록(싱크)에 `CONFIG_READ`가 포함돼 있어, `/api/v1/config` 접근 시 권한 검사를 그대로 통과한다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 하. `viewer_scopes` 목록에서 `CONFIG_READ` 한 줄을 삭제하고 `owner`용 목록에만 남기는 이동이라, "역할별 스코프 목록에 무엇이 들어있는지"를 눈으로 대조하는 것만으로 결함이 보인다.
- 재현 환경 구축 부담: 중. Fides는 웹서버·DB·Redis로 구성된 도커 컴포즈 스택이 필요해 단독 실행은 어렵지만, 공식 `docker-compose` 구성으로 한 번에 띄울 수 있어 준비 시간은 감내할 만하다.
- nuclei 템플릿 유무 / PoC 공개 여부: `gh api "/search/code?q=CVE-2023-46125+repo:projectdiscovery/nuclei-templates"` 결과 0건. 별도 공개 PoC는 확인 안 함.

## 대안 후보
5주차 business logic 후보로 쓰이는 ethyca-fides GHSA-qx5f-ghc2-7g5c와는 결함 유형이 다르다. 그쪽은 워크플로우 상태 검증 누락으로 인한 로직 우회이고, 이번 건은 역할별 스코프 정의 목록에 잘못된 값이 들어간 RBAC 설정 오류다. 같은 패키지의 다른 코드 경로이므로 두 주차에서 각각 다뤄도 중복되지 않는다.
