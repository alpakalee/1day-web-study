# 1day 분석

매주 그 주 CWE로 최근 패치를 찾아 diff를 읽는다. CVE를 많이 보는 게 목적이 아니라, 랩에서 본 패턴이 실제 코드에서 어떤 모양인지 한 번 확인하는 것이다.

선별 조건과 스크립트는 `tools/README.md`. 발표 후 노트는 `notes/TEMPLATE.md`.

## 주차별 후보 (각 3개)

각 항목은 `1day/candidates/{주차}-{CWE슬러그}-{패키지}.md`에 왜 이 후보를 뽑았는지 근거를 적어뒀다. diff 규모는 테스트·문서·락파일 제외 실코드 기준. 순서는 발표 난이도 오름차순(대략) — 앞쪽일수록 diff가 짧고 개념이 직관적이다.

### 1주 · SQL injection
| 패키지 | GHSA | diff | 결함 |
|---|---|---|---|
| Django | GHSA-gvg8-93h5-g6qq | +14/-9, 1f | 별칭 검증 정규식이 제어문자 미필터, 식별자 컨텍스트 인젝션 |
| geopandas | GHSA-6497-prx7-gpmq | +5/-1, 1f | `text()` 쓰고도 값을 f-string으로 선조립해 바인딩 무력화 |
| ormar | GHSA-xxh2-68g9-8jqr | +7/-2, 2f | `min()/max()`가 필드 검증을 건너뛰어 ORM 자체가 인젝션 통로 (critical) |

### 2주 · Auth
| 패키지 | GHSA | diff | 결함 |
|---|---|---|---|
| jupyter-scheduler | GHSA-v9g2-g7j4-4jxc | +1/-0, 1f | `@authenticated` 데코레이터 누락 |
| Flask-HTTPAuth | GHSA-p44q-vqpr-4xmg | +2/-2, 1f | 빈 토큰 기본값이 검증 콜백을 그대로 통과 |
| sentry | GHSA-7pq6-v88g-wf3w | +1/-1, 1f | SAML 신원 바인딩 검증 누락, 계정 탈취 (critical) |

### 3주 · Path traversal
| 패키지 | GHSA | diff | 결함 |
|---|---|---|---|
| GitPython | GHSA-cwvm-v4w8-q58c | +2/-0, 1f | 심볼릭 참조에 `..` 포함 여부 미검증 |
| Werkzeug | GHSA-f9vj-2wh5-fj8j | +2/-0, 1f | `safe_join()` 자체가 Windows 절대경로 우회 허용 |
| keras | GHSA-58hv-7753-xmfq | +1/-1, 1f | `abspath`→`realpath` 순서 문제로 symlink follow |

### 4주 · Command injection
| 패키지 | GHSA | diff | 결함 |
|---|---|---|---|
| dcnnt-py | GHSA-8p42-7597-p2f6 | +2/-1, 1f | 필드별 이스케이프 없이 `.format()` 조립 + `shell=True` |
| llamafactory | GHSA-hj3w-wrh4-44vp | +1/-1, 1f | 학습 인자를 f-string으로 `Popen(shell=True)`에 삽입 |
| mlflow | GHSA-rvhj-8chj-8v3c | +2/-1, 1f | `model_uri` 미이스케이프, `shlex.quote()`로 패치 (critical) |

### 5주 · Business logic
| 패키지 | GHSA | diff | 결함 |
|---|---|---|---|
| Ethyca Fides | GHSA-qx5f-ghc2-7g5c | +15/-3, 2f | 중복요청 승인 시 신원 재검증 스킵 |
| Open WebUI | GHSA-h3ww-q6xx-w7x3 | +25/-6, 2f | 첫 가입자=관리자 승격이 check-then-insert라 레이스컨디션 |
| taylored | GHSA-vh5j-5fhq-9xwg | +23/-16, 2f (39줄, 완화 기준) | 구매 토큰 검증·소비 분리로 재사용 가능 |

이 주차는 CWE 태깅 자체가 로직 결함을 못 잡아 advisory 텍스트 키워드로 우회 조사했다. 30줄 기준 통과는 8건 중 1건(Ethyca Fides)뿐이라 taylored는 40~50줄로 완화한 기준을 적용했다.

### 6주 · 정보 탐색
| 패키지 | GHSA | diff | 결함 |
|---|---|---|---|
| omero-web | GHSA-gpmg-4x4g-mr5r | +4/-5, 1f | 비밀번호 재설정 에러로 계정 존재 여부 노출(계정 열거) |
| jupyter-server | GHSA-h56g-gq9v-vc8r | +4/-5, 2f | 에러 트레이스백에 서버 경로 노출 |
| Open WebUI | GHSA-vvxm-vxmr-624h | +4/-4, 1f | 경로 순회로 `DATA_DIR` 절대경로 노출 |

### 7주 · 접근 제어
| 패키지 | GHSA | diff | 결함 |
|---|---|---|---|
| changedetection.io | GHSA-hcvp-2cc7-jrwr | +1/-0, 1f | 보호 API 엔드포인트에 인증 데코레이터 누락 |
| Ethyca Fides | GHSA-rjxg-rpg3-9r89 | +1/-1, 1f | RBAC 스코프 목록에 권한 오배치(오타성) |
| sentry | GHSA-4xqm-4p72-87h6 | +1/-1, 1f | CORS 오리진 검증이 단순 접미사 비교라 우회 가능 |

### 8주 · 파일 업로드
| 패키지 | GHSA | diff | 결함 |
|---|---|---|---|
| kiwitcms | GHSA-2fqm-m4r2-fh98 | +3/-0, 1f | SVG `onload` 속성 검증 누락, 저장형 XSS |
| Flask-Reuploaded | GHSA-937x-gpqr-72gg | +2/-0, 1f | 확장자 대소문자 비대칭으로 denylist 우회 |
| Open WebUI | GHSA-ff5c-56m7-vc75 | +21/-6, 1f | 확장자만 검사해 경로 순회 문자열 통과, 임의 파일 쓰기→RCE |

Open WebUI 건은 **advisory가 링크한 커밋이 실제 패치가 아니다** — 진짜 수정은 1년 뒤 커밋(62ab30f). 발표 자료엔 이 커밋을 써야 한다. 자세한 내용은 `1day/candidates/08-fileupload-open-webui.md` 참조.

### 9주 · SSRF
| 패키지 | GHSA | diff | 결함 |
|---|---|---|---|
| vllm | GHSA-v359-jj2v-j536 | +2/-2, 1f | 파서 불일치로 검증된 URL과 실제 요청 URL이 달라짐(TOCTOU) |
| mobsf | GHSA-m435-9v6r-v5f6 | +4/-1, 1f | `allow_redirects=True`로 302 내부망 우회 |
| weasyprint | GHSA-983w-rhvv-gwmv | +5/-2, 1f | 레거시 fetcher가 리다이렉트 자동 추적 |

### 10주 · XXE
pip/npm에 소규모 후보가 없어 maven(자바)으로 전환했다. 자바 문법은 낯설어도 파서 설정 API 이름이 명확해 diff 이해는 어렵지 않다.

| 패키지 | GHSA | diff | 결함 |
|---|---|---|---|
| xwiki-platform-xar | GHSA-gx4f-976g-7g6v | +2/-0, 1f | `disallow-doctype-decl` 미설정, DOCTYPE 자체를 못 막음 |
| wso2 carbon-mediation | GHSA-fvfq-q238-j7j3 | +2/-0, 1f | `SUPPORT_DTD` 등 StAX 파서 옵션 미설정 |
| apache xmlgraphics-fop | GHSA-jqfv-jrvq-95jm | +2/-0, 1f | `FEATURE_SECURE_PROCESSING` 미설정, XSLT 처리 중 외부 엔티티 로드 |

### 11주 · API test (BOLA)
| 패키지 | GHSA | diff | 결함 |
|---|---|---|---|
| wger | GHSA-g8gc-6c4h-jg86 | +3/-3, 1f | 소유자 필터 없이 직접 조회, 같은 파일 내 정상 패턴과 대조 가능 |
| mlflow | GHSA-8c7q-86fq-vvmh | +3/-0, 1f | MPU 업로드 경로가 인가 매핑에서 통째로 누락 (critical) |
| openwisp-ipam | GHSA-x287-5c68-36wp | +4/-2, 1f | advisory가 "broken object-level authorization" 직접 명시 |

openwisp-ipam은 **advisory가 지목한 REST API 엔드포인트(`ExportSubnetView`)가 실제로는 패치되지 않은 것으로 보인다** — 병합된 패치는 Django admin 쪽만 수정했다. 발표 전 재검증 필요, 자세한 내용은 `1day/candidates/11-api-openwisp-ipam.md` 참조.

### 12주 · NoSQL injection
pip 생태계에 정통 MongoDB 사례가 없어 npm으로 전환했다.

| 패키지 | GHSA | diff | 결함 |
|---|---|---|---|
| parse-server (npm) | GHSA-vgjh-hmwf-c588 | +6/-1, 2f | 토큰 조회 쿼리에 타입 검증 없이 `$ne` 등 연산자 주입 |
| mongoose (npm) | GHSA-m7xq-9374-9rvx | +20/-5, 2f | `populate match`에 `$where` 주입, 서버측 JS 실행까지 이어짐. **nuclei 템플릿 존재**(유일) |
| glances (pip) | GHSA-grp3-h8m8-45p7 | +25/-0, 1f | Cassandra CQL 인젝션 — 정통 NoSQLi는 아니고 pip 대체 후보 |

## 공통 관찰

- nuclei 템플릿이 있는 후보는 mongoose(12주) 하나뿐이다. Business logic·BOLA류는 애플리케이션별 로직이라 서명 기반 스캐너가 원천적으로 못 잡는다 — 재현은 PoC·요청 재구성에 의존한다.
- CWE 태깅이 카테고리를 못 잡는 주차(5주 business logic, 12주 NoSQLi)는 advisory summary 텍스트 키워드 필터를 병행해야 후보가 나온다.
- **advisory가 링크한 패치 커밋을 그대로 믿지 마라.** Open WebUI(8주)와 openwisp-ipam(11주) 두 건 모두 advisory 레퍼런스와 실제 수정 사항이 어긋났다. 발표 전에 반드시 실제 diff를 열어 advisory 설명과 일치하는지 확인한다.
