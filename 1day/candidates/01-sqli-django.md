# W1 · SQL injection — Django (GHSA-gvg8-93h5-g6qq)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2026-1287 / 2026-02-03 / high (CVSS4 8.1) / Django `< 6.0.2`, `< 5.2.11`, `< 4.2.28`
- 패치 커밋: https://github.com/django/django/commit/e891a84c7ef9962bfcc3b4685690219542f86a22
- diff 규모: `django/db/models/sql/query.py` 1파일, +14/-9

## 왜 이 주차에 적절한가
Django는 `annotate()`, `aggregate()`, `values()` 등에 넘기는 컬럼 별칭(alias)을 `check_alias()`에서 `FORBIDDEN_ALIAS_PATTERN` 정규식으로 검증한 뒤 그대로 SQL 컬럼명으로 꽂아 넣는다. 패치 전 패턴 `r"['`\"\]\[;\s]|#|--|/\*|\*/"`는 따옴표·공백·세미콜론·주석 시퀀스는 막았지만 제어문자(`\x00-\x1F`, `\x7F-\x9F`)는 걸러내지 않았다. `**kwargs` 딕셔너리 확장을 쓰면 Python 식별자 규칙을 우회해 `{"foo\x00bar": expr}` 같은 임의 문자열을 별칭으로 넘길 수 있어, 값이 아니라 "식별자(컬럼명) 자리"에 사용자 입력이 붙는 SQL 인젝션이 된다. PortSwigger SQL injection 랩 대부분은 문자열/숫자 리터럴 컨텍스트(따옴표 탈출)를 다루는데, 이 케이스는 파라미터 바인딩이 애초에 불가능한 식별자 컨텍스트(예: `ORDER BY` 절 인젝션 랩과 같은 계열) 문제라 "왜 준비된 문(prepared statement)만으로는 못 막는 SQLi가 있는가"를 보여주는 대비 사례로 좋다.

## 취약점 한 줄 요약
`QuerySet.annotate/aggregate/extra/values/values_list/alias`에 `**kwargs`로 전달되는 별칭 문자열(딕셔너리 키, 제어문자 포함 가능)이 `check_alias()`의 블랙리스트 정규식을 통과해 컬럼 별칭으로 그대로 SQL에 삽입된다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 중. 정규식 한 줄과 에러 메시지 문자열만 바뀌어 diff 자체는 짧지만, "왜 값이 아니라 별칭에 인젝션이 되는지", "`**{"key\x00": ...}`로 Python 식별자 제약을 우회한다는 점"을 별도로 설명해야 30줄만 보고 이해되지 않는다.
- 재현 환경 구축 부담: 중~상. Django ORM으로 `FilteredRelation` + `annotate(**{...})`를 호출하는 뷰를 직접 만들어야 하고, 제어문자가 실제로 어떤 DB 백엔드(SQLite/MySQL/PostgreSQL)에서 어떻게 SQL을 깨는지 확인하려면 각 백엔드의 식별자 인용 규칙까지 봐야 함. 발표용 PoC 구현에는 다소 시간이 든다.
- nuclei 템플릿 유무 / PoC 공개 여부: `gh api "/search/code?q=CVE-2026-1287+repo:projectdiscovery/nuclei-templates"` 결과 0건, nuclei 템플릿 없음. 공개 PoC 미확인(advisory·커밋 메시지 외 별도 exploit 코드 확인 안 함).

## 대안 후보
확인 안 함.
