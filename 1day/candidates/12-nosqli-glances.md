# W12 · NoSQL injection — glances (GHSA-grp3-h8m8-45p7)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2026-35588 / 2026-04-21 / medium (CVSS3.1 6.3) / glances (pip) `< 4.5.4`
- 패치 커밋: https://github.com/nicolargo/glances/commit/d339181f03a14bb15506307e9d58f876e23d8160 (병합 커밋 https://github.com/nicolargo/glances/commit/e41b665576f9fd5374e3152078726cc59a01e48c)
- diff 규모: `glances/exports/glances_cassandra/__init__.py` 1파일, +25/-0

## 왜 이 주차에 적절한가 (그리고 왜 애매한가)
Cassandra export 모듈이 `glances.conf`의 `keyspace`/`table`/`replication_factor` 값을 검증 없이 f-string으로 CQL 문에 꽂아 넣는다(`f"CREATE KEYSPACE {self.keyspace} WITH replication = {{ 'class': 'SimpleStrategy', 'replication_factor': '{self.replication_factor}' }}"`, `f"INSERT INTO {self.table} (...) VALUES (?, ?, ?)"`). 패치는 `_CQL_IDENTIFIER_RE = re.compile(r'^[a-zA-Z][a-zA-Z0-9_]*$')`로 `keyspace`/`table`을 검증하고 `replication_factor`를 `int()`로 강제 캐스팅하는 가드를 추가했다. 다만 솔직히 말하면 이건 PortSwigger가 다루는 "NoSQL injection"(MongoDB 쿼리 연산자 조작, 인증/인가 우회) 개념과는 결이 다르다. CQL(Cassandra Query Language)은 문법상 SQL에 훨씬 가깝고(`CREATE KEYSPACE`, `INSERT INTO` 등 동일한 키워드), advisory 자체도 CWE-89(SQL Injection)로 분류돼 있다. "NoSQL 데이터스토어를 대상으로 한 쿼리 언어 인젝션"이라는 넓은 의미에서만 12주차와 연결되고, mongoose·parse-server 두 건이 보여주는 "쿼리를 객체/연산자로 표현하기 때문에 생기는" 전형적 NoSQLi 패턴과는 공격 메커니즘이 다르다.
- 공격자 모델도 다르다: mongoose/parse-server는 인증 없는 외부 공격자가 HTTP 요청 하나로 트리거하지만, 이 건은 "`glances.conf` 파일에 쓰기 권한이 있는 사람"이 전제(CVSS `AV:L/PR:H`)라 이미 상당한 권한을 가진 내부자/설정 관리자 시나리오에 가깝다.

## 취약점 한 줄 요약
`glances.conf`의 `[cassandra]` 섹션에서 읽어온 `keyspace`/`table`/`replication_factor` 설정값이 검증 없이 `CREATE KEYSPACE`/`CREATE TABLE`/`INSERT INTO` CQL 문자열에 f-string으로 직접 삽입되어, 예를 들어 `table = attacker_ks.captured_stats`처럼 다른 키스페이스로 모니터링 데이터를 리다이렉트시킬 수 있다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 하. `_validate_cql_identifier()` 함수 하나(정규식 매치 실패 시 `ValueError`)와 `__init__()`에서 이를 호출하는 블록만 추가된 전형적인 화이트리스트 검증 패치라 코드 자체는 쉽게 읽힌다. 다만 "왜 굳이 pip 생태계에서 CQL 인젝션을 다루는가"를 스터디에서 설명하려면 CQL과 NoSQL의 관계, 그리고 이 건이 PortSwigger 랩과 결이 다르다는 점을 먼저 짚어야 한다.
- 재현 환경 구축 부담: 상. Cassandra(또는 Scylla) 클러스터 구동이 필요하고, glances를 `--export cassandra` 옵션으로 실제로 붙여야 한다. advisory PoC는 공격자 소유 키스페이스를 미리 만들어두고 `glances.conf`의 `table` 값을 조작하는 시나리오라, Docker로 Cassandra를 띄우는 것부터 스터디 준비 부담이 mongoose/parse-server보다 크다.
- nuclei 템플릿 유무 / PoC 공개 여부: `gh api "/search/code?q=CVE-2026-35588+repo:projectdiscovery/nuclei-templates"` 결과 0건, nuclei 템플릿 없음(애초에 네트워크로 원격 트리거하는 취약점이 아니라 설정 파일 기반이라 nuclei 스캔 대상 자체가 아님). advisory에 PoC 스크린샷(`n0z0/cve-evidence` 저장소 이미지)이 링크돼 있으나 실행 가능한 PoC 코드 자체는 공개되지 않음.

## 대안 후보
mongoose(정통 MongoDB `$where` 연산자, nuclei 템플릿·OOB PoC 존재)·parse-server(좁지만 명확한 NoSQL 연산자 인젝션) 두 건이 이미 "NoSQLi 개념"을 정확히 대표하므로, 이 건을 3번째 후보로 넣는 이유는 pip 생태계에는 정통 MongoDB 인젝션 소규모 후보가 사실상 없다는 현실적 제약 때문이다. glances 건은 CVE 검색 범위(pip)에서 찾은 사실상 유일한 "NoSQL류 쿼리 언어 인젝션" 사례이지만, 발표 시 "이건 엄밀히는 SQL 인젝션에 더 가깝고 공격자 모델도 다르다"는 점을 먼저 밝히고 대체/보충 사례로 위치시키는 게 정직하다. 3개 중 하나를 꼭 골라야 한다면 mongoose > parse-server > glances 순으로 주제 적합도가 높다.
