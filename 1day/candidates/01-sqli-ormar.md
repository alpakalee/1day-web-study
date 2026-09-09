# W1 · SQL injection — ormar (GHSA-xxh2-68g9-8jqr)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2026-26198 / 2026-06 무렵(advisory `published_at` 미노출, 릴리스 0.23.0 기준) / critical / ormar (pip) `0.9.9–0.12.2`, `0.20.0b1–0.22.0`
- 패치 커밋: https://github.com/collerek/ormar/commit/a03bae14fe01358d3eaf7e319fcd5db2e4956b16
- diff 규모(실측): 보안 수정 자체는 `ormar/queryset/queryset.py` 1파일 +6/-1. 같은 커밋에는 `docs/releases.md`(+22/-2), `pyproject.toml`(+1/-1), 신규 테스트 `tests/test_vulnerabilities/test_aggregated_functions.py`(+69/-0)도 포함되어 전체는 +98/-4 5파일.

## 왜 이 주차에 적절한가
ormar는 `QuerySet.min()`/`max()`에 넘어온 컬럼 문자열을 `SelectAction.get_text_clause()`에서 `sqlalchemy.text(f"{alias}{self.field_name}")`로 그대로 SQL 텍스트로 만든 뒤 `func.max(...)`/`func.min(...)`으로 감싼다. `sum()`/`avg()`는 `_query_aggr_function()`에서 `is_numeric` 검사를 거치지만, 이 검사는 `func_name in ["sum", "avg"]`일 때만 실행돼 `min()`/`max()`는 완전히 무검증 상태였다. Django·geopandas 건이 "값 조립 방식"의 문제였다면, 이 건은 **ORM이 제공하는 쿼리 빌더 메서드 자체가 사용자 입력을 검증 없이 SQL로 승격**시키는 문제라, "ORM을 쓰면 SQLi가 자동으로 사라진다"는 흔한 오해를 반박하는 사례로 이번 주차에 강하게 들어맞는다.

## 취약점 한 줄 요약
`Model.objects.max(column)` / `.min(column)`에 전달된 `column` 문자열(예: REST API의 `?column=` 쿼리 파라미터)이 모델 필드 존재 여부 검증 없이 `sqlalchemy.text()`를 거쳐 `SELECT max(<column>) ... FROM (...)` SQL의 컬럼 표현식 자리에 그대로 삽입되어, 서브쿼리(`(SELECT ... FROM sqlite_master)`)까지 실행 가능한 완전한 SQL 인젝션 싱크가 된다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 하~중. 패치는 `if any(x.field_name not in x.target_model.model_fields for x in select_actions): raise QueryDefinitionError(...)` 한 블록 추가가 전부라 diff 자체는 짧다. 다만 "왜 sum/avg는 안전하고 min/max만 뚫려있었는지"(`is_numeric` 체크의 조건문 스코프 문제)를 짚어주지 않으면 패치 의도가 잘 안 보인다.
- 재현 환경 구축 부담: 하. advisory에 첨부된 PoC가 공식 ormar FastAPI 예제(`examples/fastapi_quick_start.py`)에 `/items/stats?metric=max&column=<input>` 엔드포인트 하나만 얹은 형태라, `pip install ormar databases aiosqlite fastapi uvicorn` 후 그대로 실행하면 재현된다. SQLite만으로 되고, advisory는 PostgreSQL/MySQL에서도 서브쿼리 문법이 동일하게 통한다고 명시.
- nuclei 템플릿 유무 / PoC 공개 여부: `gh api "/search/code?q=CVE-2026-26198+repo:projectdiscovery/nuclei-templates"` 결과 0건, nuclei 템플릿 없음. advisory 자체에 풀 PoC 서버(`poc_server.py`)와 공격 스크립트(`poc_attacker.py`)가 6단계 공격 시나리오(인젝션 확인 → 테이블 열거 → 스키마 추출 → 자격증명 덤프 → 블라인드 추출 → API 키 탈취)로 전부 공개되어 있어 별도 PoC 작성 부담이 거의 없음.

## 대안 후보
01-sqli-django.md(식별자 컨텍스트, 블랙리스트 정규식 우회)·01-sqli-geopandas.md(바인딩 API 오용) 대비, 이 건은 유일하게 "severity: critical"이자 공개 PoC가 가장 완성도 높아 발표용 데모로는 제일 강하다. 다만 취약점이 `min()`/`max()`라는 특정 API 두 개에 국한돼 "ORM 전반이 위험하다"는 과장된 인상을 주지 않도록, `sum()`/`avg()`는 애초에 부분적으로 안전했다는 점을 발표에서 함께 짚어야 한다.
