# W1 · SQL injection — geopandas (GHSA-6497-prx7-gpmq)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2025-69662 / 2026-01-30 / high (CVSS3.1 8.6) / geopandas (pip) `< 1.1.2`
- 패치 커밋: https://github.com/geopandas/geopandas/commit/6aa8ef14ffdee4ba1044349ab948e1a1fbfaf419
- diff 규모: `geopandas/io/sql.py` 1파일, +5/-1 (같은 커밋의 `CHANGELOG.md` +1/-0은 문서 변경)

## 왜 이 주차에 적절한가
`_write_postgis()`가 SRID 확인용 쿼리를 만들 때 `text(f"SELECT Find_SRID('{schema_name}', '{name}', '{geom_name}');")`처럼 SQLAlchemy `text()`를 쓰면서도 정작 안에 넣는 값 세 개(`schema_name`, `name`, `geom_name`)는 전부 Python f-string으로 직접 문자열에 꽂아 넣었다. `text()`는 파라미터 바인딩(`:placeholder` + `.bindparams()`)을 지원하는 API인데, 그 API를 쓰고도 f-string으로 값을 미리 조립해버려 바인딩이 무의미해진 케이스다. 01-sqli-django.md가 "바인딩이 원천적으로 불가능한 식별자 컨텍스트"를 보여준다면, 이 건은 반대로 "바인딩 가능한 API가 이미 있는데 개발자가 안 쓴" 사례라 같은 주차 안에서 뚜렷한 대비가 된다.

## 취약점 한 줄 요약
`GeoDataFrame.to_postgis()` 호출 시 지오메트리 컬럼명(`geom_name`, 테이블이 이미 존재할 때 SRID를 검증하는 경로)이 검증·이스케이프 없이 f-string으로 `Find_SRID(...)` SQL 문자열에 직접 삽입되어 PostgreSQL로 그대로 전달된다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 하. 패치가 f-string 한 줄을 `text(...).bindparams(...)`로 바꾼 것뿐이라 "왜 이게 안전해지는지"를 파라미터 바인딩 개념 한 번만 설명하면 바로 이해된다. Django 건보다 진입장벽이 낮아 입문용으로 적합.
- 재현 환경 구축 부담: 중. PostGIS가 설치된 PostgreSQL 인스턴스가 필요하고(`Find_SRID` 자체가 PostGIS 함수), `to_postgis()`를 호출하기 전에 대상 테이블이 이미 존재하는 상태를 만들어야 이 SRID 체크 경로를 탄다. Docker로 `postgis/postgis` 이미지를 띄우면 부담은 크지 않음.
- nuclei 템플릿 유무 / PoC 공개 여부: `gh api "/search/code?q=CVE-2025-69662+repo:projectdiscovery/nuclei-templates"` 결과 0건, nuclei 템플릿 없음. advisory references에 블로그 PoC(`aydinnyunus.github.io/2025/12/27/sql-injection-geopandas`)가 걸려 있으나 본 조사에서 원문 내용까지는 확인하지 않음.

## 대안 후보
같은 주차의 01-sqli-django.md(별칭 정규식 우회, 식별자 컨텍스트), 01-sqli-ormar.md(ORM 쿼리 빌더 자체의 검증 누락)와 비교하면, 이 건은 "파라미터 바인딩 API를 쓰고도 잘못 쓴" 가장 단순한 실수형 사례라 초심자 도입부로 배치하기 좋다. 다만 공격 표면이 `to_postgis()`를 호출하는 애플리케이션 코드가 사용자 입력으로 지오메트리 컬럼명/테이블명을 결정하는 특수한 경우로 한정돼, django/ormar 건보다 "누가 이걸 트리거하는가"에 대한 스토리텔링이 한 단계 더 필요하다.
