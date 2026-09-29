# Django column alias SQL Injection

> 분석 흐름 도식: [analysis.excalidraw](./analysis.excalidraw)

> [`CVE-2026-1287` · `GHSA-gvg8-93h5-g6qq`](https://github.com/advisories/GHSA-gvg8-93h5-g6qq)  
> Django `< 6.0.2`, `< 5.2.11`, `< 4.2.28` 영향 · 각 버전에서 수정

## Django ORM과 column alias

[Django](https://www.djangoproject.com/)는 Python으로 웹 애플리케이션을 만드는 프레임워크다. Django ORM을 사용하면 Python의 모델과 `QuerySet` 메서드로 데이터베이스를 조회할 수 있다.

```python
class Author(models.Model):
    name = models.CharField(max_length=100)
    age = models.IntegerField()
```

`aggregate()`는 표 전체를 계산해서 하나의 요약값을 구할 때 사용한다. 예를 들어 저자 여러 명의 나이를 계산해 전체 평균 하나를 반환한다.

```text
저자 나이: 20, 30, 40
aggregate(평균) → 30
```

`annotate()`는 각 행에 계산한 값을 하나씩 붙일 때 사용한다. 예를 들어 저자마다 작성한 책의 수를 계산해 각 저자 옆에 표시한다.

```text
Alice → 책 3권
Bob   → 책 1권
```

이번 취약점에서는 두 기능이 계산 결과에 붙이는 이름인 alias를 받는다는 점이 중요하다.

```python
from django.db.models import Avg

Author.objects.aggregate(average_age=Avg("age"))
```

```python
{"average_age": 31.5}
```

여기서 `average_age`는 계산 결과에 붙인 이름인 column alias다.

SQL의 `AS`는 열이나 테이블에 임시 이름을 붙이는 문법이다. 다음 SQL은 `AVG(age)`로 계산한 결과를 `average_age`라는 이름으로 보여 달라는 뜻이다.

```sql
SELECT AVG("author"."age") AS "average_age"
FROM "author";
```

```text
AVG(age)       실제 계산식
AS             "이 결과를 다음 이름으로 부르겠다"
average_age    붙인 이름(alias)
```

`31.5` 같은 데이터 값과 달리 `average_age`는 생성되는 SQL 문장의 열 이름이 된다.

## `FilteredRelation`은 무엇인가

서로 다른 표에 나뉜 데이터를 함께 볼 때 SQL의 `JOIN`을 사용한다.

```text
restaurants                 pizzas
┌────┬──────┐               ┌────┬───────────────┬───────────────┐
│ id │ name │               │ id │ restaurant_id │ name          │
├────┼──────┤               ├────┼───────────────┼───────────────┤
│ 1  │ A식당│               │ 10 │ 1             │ mozzarella    │
└────┴──────┘               └────┴───────────────┴───────────────┘
```

`JOIN`은 두 표를 합쳐서 조회하라는 뜻이고, `ON`은 어느 행끼리 연결할지 정하는 조건이다.

```sql
SELECT *
FROM restaurants
JOIN pizzas
  ON restaurants.id = pizzas.restaurant_id;
```

여기서는 식당의 `id=1`과 피자의 `restaurant_id=1`이 같으므로 두 행이 연결된다.

`FilteredRelation`은 이 `ON` 조건에 추가 필터를 넣는 Django ORM 기능이다. 예를 들어 모든 피자가 아니라 채식 피자만 JOIN할 수 있다.

```sql
ON restaurants.id = pizzas.restaurant_id
AND pizzas.vegetarian = TRUE
```

```python
from django.db.models import FilteredRelation, Q

Restaurant.objects.annotate(
    vegetarian_pizzas=FilteredRelation(
        "pizzas",
        condition=Q(pizzas__vegetarian=True),
    )
).filter(
    vegetarian_pizzas__name__icontains="mozzarella"
)
```

위 코드에서 `vegetarian_pizzas`는 필터링된 JOIN 결과를 가리키는 alias다. 개념적으로 다음과 같은 SQL을 만드는 데 사용된다.

```sql
SELECT ...
FROM restaurant
INNER JOIN pizza AS vegetarian_pizzas
    ON restaurant.id = vegetarian_pizzas.restaurant_id
   AND vegetarian_pizzas.vegetarian = TRUE
WHERE vegetarian_pizzas.name LIKE '%mozzarella%';
```

실제 테이블명과 인용 문법은 사용하는 DB backend에 따라 달라질 수 있다.

## 취약점 요약

Django는 `annotate()`, `aggregate()` 등에 전달된 alias가 SQL 문법을 포함하지 못하도록 `check_alias()`에서 금지 문자를 검사했다.

그러나 기존 정규식은 따옴표, 공백, 세미콜론, 주석 기호 등은 막았지만 전체 제어문자 범위를 검사하지 않았다. `FilteredRelation`이 포함된 쿼리에서 특수하게 만든 alias가 검사를 통과해 SQL 구조에 영향을 줄 수 있었다.

```text
외부에서 만들어진 문자열
    ↓
딕셔너리의 key
    ↓
QuerySet 메서드의 **kwargs
    ↓
column alias
    ↓
check_alias()의 정규식 검사
    ↓ 제어문자 일부가 통과
SQL의 식별자 자리
```

공식 advisory가 명시한 영향 메서드는 다음과 같다.

```text
annotate()
aggregate()
extra()
values()
values_list()
alias()
```

## 왜 `**kwargs`가 필요한가

`kwargs`는 Python에서 함수에 `이름=값` 형태로 전달하는 인자들을 뜻한다. `keyword arguments`를 줄인 이름이다.

```python
def introduce(name, age):
    print(name, age)

introduce(name="Alice", age=20)
```

여기서 `name`과 `age`가 인자의 이름이고 `"Alice"`와 `20`이 값이다.

`**`는 딕셔너리에 들어 있는 `이름: 값` 쌍을 `이름=값` 형태의 인자들로 펼친다.

```python
data = {"name": "Alice", "age": 20}
introduce(**data)

# Python은 위 호출을 다음과 같은 의미로 처리한다.
introduce(name="Alice", age=20)
```

Django의 `aggregate()`와 `annotate()`에서는 이 인자의 이름을 SQL 결과의 alias로 사용한다.

보통 alias는 코드에 직접 작성한다.

```python
Author.objects.aggregate(average_age=Avg("age"))
```

하지만 `**`로 딕셔너리를 펼치면 실행 중에 만들어진 문자열을 인자 이름, 즉 alias로 전달할 수 있다.

```python
alias = "average_age"

Author.objects.aggregate(
    **{alias: Avg("age")}
)
```

두 호출의 정상적인 의미는 같다. 차이는 두 번째 코드의 alias가 고정된 Python 코드가 아니라 파일, 요청값 또는 다른 함수에서 전달된 문자열일 수 있다는 점이다.

```text
{"average_age": Avg("age")}
         ↓ **로 펼치기
aggregate(average_age=Avg("age"))
```

Python은 `**`로 펼치는 딕셔너리의 key가 문자열이면 일반적인 변수 이름으로 작성하기 어려운 문자도 전달할 수 있다.

```python
alias = "name\x00suffix"
queryset.annotate(**{alias: Value(1)})
```

즉 `**kwargs`가 취약한 기능이라는 뜻은 아니다. 공격자가 조작한 문자열도 alias가 될 수 있으므로 Django가 그 문자열 전체를 안전하게 검사해야 한다는 뜻이다.

## 취약한 검사 코드

Django의 `Query.check_alias()`는 alias에 금지된 문자가 있는지 정규식으로 검색한다.

```python
def check_alias(self, alias):
    if FORBIDDEN_ALIAS_PATTERN.search(alias):
        raise ValueError(
            "Column aliases cannot contain ..."
        )
```

패치 전 정규식은 다음과 같았다.

```python
FORBIDDEN_ALIAS_PATTERN = _lazy_re_compile(
    r"['`\"\]\[;\s]|#|--|/\*|\*/"
)
```

각 부분의 의미는 다음과 같다.

| 정규식 | 차단 대상 |
|---|---|
| `'`, `"`, backtick | 문자열·식별자 인용 문자 |
| `[`, `]` | 일부 DB의 식별자 인용 문자 |
| `;` | SQL 문장 구분자 |
| `\s` | 공백으로 분류되는 문자 |
| `#`, `--`, `/*`, `*/` | SQL 주석 문법 |

문제는 “공백으로 분류되는 제어문자”와 “전체 제어문자”가 같지 않다는 점이다.

## 제어문자란 무엇인가

제어문자는 화면에 글자로 출력하기보다 장치나 문자열 처리를 제어하기 위해 정의된 문자다.

```text
NUL       \x00
Tab       \x09
Line Feed \x0A
Escape    \x1B
Delete    \x7F
```

기존 정규식의 `\s`는 공백으로 판단되는 일부 문자를 막는다. 하지만 `\x00`이나 `\x1B`처럼 공백으로 분류되지 않는 제어문자까지 모두 뜻하지는 않는다.

이런 문자는 Python, Django, DB 드라이버와 데이터베이스 파서가 서로 다르게 처리할 수 있다. 한 계층에서는 alias의 일부로 통과했지만 다음 계층에서는 구분자처럼 처리되거나 제거되면, Django가 검사한 문자열과 DB가 해석한 SQL의 경계가 달라질 수 있다.

## 검사를 통과하는 과정

예를 들어 alias에 눈에 보이지 않는 `NUL` 문자가 들어 있다고 가정한다.

```python
alias = "report\x00name"
```

패치 전 검사의 흐름은 다음과 같다.

```text
report\x00name
    ↓
따옴표 없음
세미콜론 없음
주석 기호 없음
\x00은 \s에 해당하지 않음
    ↓
FORBIDDEN_ALIAS_PATTERN 검색 결과 없음
    ↓
alias 검사 통과
```

이 예시는 정규식 누락을 보여준다. `report\x00name` 자체가 완성된 공격 페이로드라는 뜻은 아니다.

실제 SQL Injection은 `FilteredRelation` 쿼리 구조, 사용한 제어문자 조합, DB backend의 해석이 함께 맞아야 한다. 공식 advisory는 “적절히 조작된 딕셔너리”라고 설명하지만 완전한 공격 문자열과 생성 SQL은 공개하지 않았다. 따라서 공개 근거 없이 특정 문자열을 작동하는 PoC로 단정해서는 안 된다.

## 제어문자가 실제로 위험해지는 경우

제어문자가 위험한 이유는 단순히 화면에 보이지 않기 때문이 아니다. 한 계층에서는 문자열의 일부로 검사했지만 다음 계층에서는 **공백, 문자열 끝, 파일 끝, 새 레코드**로 해석할 수 있기 때문이다.

### 1. 탭과 줄바꿈을 SQL 공백으로 사용하는 경우

SQL 파서는 일반 공백뿐 아니라 탭과 줄바꿈으로도 토큰을 구분한다. 따라서 공백 한 칸만 찾는 단순한 필터라면 다음 두 입력을 다르게 검사해도 DB는 비슷한 SQL 구조로 해석할 수 있다.

```text
OR 1=1
OR\t1=1       # HT, 0x09
UNION\nSELECT # LF, 0x0A
```

HTTP 요청에서는 탭과 줄바꿈이 `%09`, `%0A`처럼 전달될 수 있다. 이는 SQL Injection 필터 우회에서 실제로 조사할 가치가 있는 제어문자 사용법이다.

다만 CVE-2026-1287의 패치 전 정규식에도 `\s`가 있었다. Python에서 HT(`0x09`), LF(`0x0A`), VT(`0x0B`), FF(`0x0C`), CR(`0x0D`)은 `\s`에 포함되므로 이 문자들은 이미 alias 검사에서 차단됐다. **위험한 일반 사례이지만 이번 CVE의 공개되지 않은 핵심 문자를 설명하는 증거는 아니다.**

### 2. NUL로 검사 결과와 사용 결과가 달라지는 경우

NUL(`0x00`)은 C 계열 API에서 문자열의 끝을 의미하는 경우가 있다. 상위 계층은 `safe\x00suffix` 전체를 검사했는데 하위 계층은 `safe`까지만 사용하면 두 계층이 서로 다른 문자열을 보게 된다.

```text
검사 계층: safe\x00suffix
사용 계층: safe
```

CAPEC-52와 OWASP는 이를 **NULL byte injection**으로 분류한다. 파일 확장자 검사 우회, 뒤에 강제로 붙인 문자열 제거, 검증기와 네이티브 API 사이의 해석 차이가 대표적인 결과다. SQL에서도 애플리케이션 → Django → DB 드라이버 → DB 서버 중 어느 경계에서 문자열이 잘리거나 거부되는지가 중요하다.

이것은 제어문자가 실제 취약점에 이용되는 명확한 사례다. 그러나 `report\x00name`이 CVE-2026-1287에서 동작하는 SQL Injection 페이로드라는 뜻은 아니다. 공개 advisory에는 사용된 문자, DB, 완성된 페이로드가 없다.

### 3. 파일 끝이나 새 레코드로 해석되는 경우

MySQL 문서에는 Control+Z(`0x1A`)가 Windows에서 파일 끝(EOF)을 의미해 SQL 파일을 가져올 때 문제가 될 수 있다고 명시되어 있다. 같은 바이트가 SQL 문자열의 일부인지, 입력 파일의 끝인지 처리 계층에 따라 달라지는 사례다.

CR(`0x0D`)과 LF(`0x0A`)도 로그에서는 새 줄을 만든다. 사용자 입력을 그대로 기록하면 공격자가 정상 로그 뒤에 가짜 로그 한 줄을 삽입할 수 있다. 이는 SQL alias 공격은 아니지만, 보이지 않는 문자가 **데이터의 경계 자체를 바꾸는 실제 보안 문제**라는 점을 보여준다.

## CVE-2026-1287에서 확인된 것과 확인되지 않은 것

| 구분 | 내용 |
|---|---|
| 확인됨 | `FilteredRelation`이 포함된 쿼리에서 사용자 제공 alias와 제어문자 검사가 문제였다. |
| 확인됨 | 패치는 C0(`0x00–0x1F`)과 C1(`0x7F–0x9F`) 전체를 SQL 생성 전에 거부한다. |
| 확인됨 | 패치의 회귀 테스트는 범위 안의 모든 문자가 각 QuerySet 경로에서 `ValueError`를 내는지 검사한다. |
| 실증됨 | `FilteredRelation` alias는 SQL에 따옴표 없이 삽입된다 (`quote_name_unless_alias()`). |
| 실증됨 | 패치 전 정규식은 55개 제어문자 + 24개 ASCII 특수문자 = 79개 문자를 통과시킨다. |
| 실증됨 | alias에 `%s`를 넣으면 psycopg2의 파라미터 바인딩이 꼬여 `IndexError` 크래시가 발생한다 (DoS). |
| 실증됨 | alias를 기존 테이블명(`poc_author`)과 동일하게 하면 Django가 FROM 절의 원래 테이블을 제거해 SQL 구조가 파괴된다. |
| 실증됨 | PG에서 C1 문자(`0x80`~`0x9F`)는 psycopg2가 UTF-8로 인코딩하고 PG가 제어문자를 제거해 컬럼명이 변형된다. |
| 실증됨 | MariaDB 10.11에서 C0 문자(`0x01`~`0x1B`)는 unquoted alias에서 syntax error를 일으킨다 (PG와 다른 동작). |
| 실증됨 | 패치 후에도 `%`, `(`, `)`, `,`, `.` 등 24개 SQL 연산자·구분자가 check_alias를 통과한다. |
| 미달성 | 테스트한 모든 DB(PG 16, MySQL 8.0, MariaDB 10.11)에서 완전한 SQL Injection(다른 테이블 데이터 읽기)은 달성하지 못했다. |
| 공개되지 않음 | 실제 공격에 사용된 제어문자, 대상 DB, 완성된 payload, 최종 생성 SQL. |

## 실증 테스트 결과

Django 5.2.10(패치 전), PostgreSQL 16, MySQL 8.0, MariaDB 10.11 환경에서 검증했다. 테스트 코드: `../../tmp/test_*.py`.

### 1. unquoted alias 확인

`FilteredRelation` alias는 `compiler.py`의 `quote_name_unless_alias()`에서 따옴표가 생략된다. 정상 alias `pub`로 생성한 SQL에서 확인했다.

```sql
INNER JOIN “poc_book” pub ON (“poc_author”.”id” = pub.”author_id”)
```

`pub`에 따옴표가 없다. 공격자가 alias에 SQL 연산자나 키워드를 넣으면 SQL 구조가 변할 수 있는 위치다.

### 2. 토큰 분리 문자

unquoted alias에 포함된 특수문자가 SQL 파서에서 토큰을 분리하는지 테스트했다.

| 문자 | PostgreSQL 16 | MySQL 8.0 | MariaDB 10.11 |
|---|---|---|---|
| `+` | 분리 | 분리 | 분리 |
| `-` | 분리 | 분리 | 분리 |
| `@` | 분리 | 분리 | 분리 |
| `~` | 분리 | 분리 | 분리 |
| `.` | 분리 | — | — |
| `!` | — | 분리 | 분리 |

제어문자(C0·C1)는 PG에서 토큰 분리 없이 식별자에 포함되거나 제거됐고, MariaDB에서는 syntax error로 거부됐다.

### 3. `%s` alias → 파라미터 바인딩 크래시 (DoS)

alias에 `%s`가 포함되면 psycopg2가 이를 파라미터 플레이스홀더로 해석해 `IndexError`가 발생한다.

```python
Author.objects.aggregate(**{“x%sx”: Avg(“id”)})
# IndexError: tuple index out of range
```

생성된 SQL에 `AS “x%sx”`가 들어가고, psycopg2가 `%s`를 바인딩하려 하지만 대응하는 파라미터가 없어 크래시한다. `%` 문자는 패치 후 정규식에도 포함되지 않으므로 **패치 후에도 유효한 DoS 벡터**다.

### 4. alias shadowing → SQL 구조 파괴

alias를 기존 테이블명과 동일하게 설정하면 Django 내부에서 테이블 참조가 충돌한다.

```python
Author.objects.annotate(
    poc_author=FilteredRelation(“books”, condition=Q(books__is_published=True))
).annotate(cnt=Count(“poc_author__id”))
```

생성된 SQL에서 원래 FROM 절의 `”poc_author”`가 사라진다.

```sql
SELECT ... FROM LEFT OUTER JOIN “poc_book” poc_author ON (...)
--               ↑ FROM 뒤에 바로 JOIN — 기본 테이블 없음
```

`ProgrammingError: syntax error at or near “OUTER”` — SQL이 구조적으로 깨진다.

### 5. SQL Injection이 달성되지 않는 이유

| 필요 조건 | 상태 |
|---|---|
| SQL 키워드(`FROM`, `JOIN`, `OR`) 삽입 | 키워드는 공백으로 분리해야 하는데 `\s`가 차단 |
| 괄호로 서브쿼리 삽입 | `(`, `)`는 통과하지만 JOIN 컨텍스트에서 syntax error |
| `,`로 추가 테이블 참조 | `LEFT OUTER JOIN ... x,secrets ON (...)` → PG syntax error |
| 연산자(`+`, `-`)로 키워드 분리 | SELECT/WHERE 내에서만 토큰 분리, FROM/JOIN 후에는 불가 |
| `$`로 dollar-quoting | Django가 `$`를 별도 검증으로 차단 |

연산자는 SQL 값 컨텍스트에서 토큰을 분리하지만, SQL 절(`FROM`, `JOIN`, `ON`)의 구조를 바꾸지는 못한다. `FROM+poc_author`는 syntax error다.

### 6. 패치 후 잔존하는 공격면

패치는 C0·C1 제어문자를 차단했지만 24개 ASCII 특수문자와 24개 Latin-1 특수문자는 여전히 통과한다.

```text
패치 후에도 통과하는 위험 문자:
% → psycopg2 파라미터 플레이스홀더 (%s 크래시)
( ) → SQL 괄호
, → SQL 구분자
. → 스키마·테이블 구분
+ - * / → SQL 산술 연산자
= < > → SQL 비교 연산자
| & ^ ~ → SQL 비트 연산자
: → PG 타입 캐스트 (::)
? → PG JSON 연산자
@ → PG 연산자
```

현재 이 문자들로 완전한 SQL Injection은 달성되지 않지만, `%s` DoS와 alias shadowing은 패치 후에도 가능하다. 이는 denylist 방식의 한계를 보여준다.

## 공개 패치로 확인할 수 있는 재현

패치 커밋의 회귀 테스트는 모든 C0·C1 제어문자가 alias로 거부되는지 확인한다.

```python
from itertools import chain

crafted_aliases = (
    f"name{chr(code)}"
    for code in chain(
        range(32),
        range(0x7F, 0xA0),
    )
)

for crafted_alias in crafted_aliases:
    with self.assertRaisesMessage(ValueError, message):
        Author.objects.aggregate(
            **{crafted_alias: Avg("age")}
        )
```

검사하는 범위는 다음과 같다.

```text
\x00–\x1F  C0 제어문자 32개
\x7F–\x9F  DEL과 C1 제어문자 33개
```

패치 전에는 이 가운데 기존 정규식의 `\s`에 포함되지 않는 문자가 검사를 통과할 수 있었다. 패치 후에는 SQL을 생성하기 전에 모든 문자가 `ValueError`로 거부된다.

## 패치

패치는 기존 정규식에 두 제어문자 범위를 추가했다.

```python
FORBIDDEN_ALIAS_PATTERN = _lazy_re_compile(
    r"['`\"\]\[;\s\x00-\x1F\x7F-\x9F]|#|--|/\*|\*/"
)
```

패치 전후의 차이는 다음 부분이다.

```text
패치 전: \s
패치 후: \s + \x00-\x1F + \x7F-\x9F
```

```text
조작된 alias
    ↓
check_alias()
    ↓ 제어문자 범위에서 발견
ValueError
    ↓
SQL compiler와 DB까지 도달하지 않음
```

이 문제는 일반적인 SQL 값의 매개변수화와는 성격이 다르다.

```sql
SELECT * FROM author WHERE age > %s;
                                 └ 값 자리

SELECT AVG(age) AS average_age FROM author;
                   └ SQL 식별자 자리
```

DB의 값 placeholder는 보통 열 이름이나 alias를 대신할 수 없다. Django는 alias가 SQL 구조를 바꾸는 문자를 포함하지 못하도록 별도로 검사한다.

패치 커밋 전체는 릴리스 문서와 여러 QuerySet 메서드의 테스트를 포함해 8개 파일 `+149/-59`다. 실제 검사 로직을 바꾼 `django/db/models/sql/query.py`의 변경은 `+14/-9`다.

## 추가로 조사할 분야

### 1. 취약 버전에서 문자별·DB별 결과 기록

패치 전 Django에 C0·C1 문자를 하나씩 넣고 PostgreSQL, MySQL·MariaDB, SQLite에서 다음 결과를 수집한다.

```text
입력값의 repr()
check_alias() 통과 여부
DB 드라이버에 전달되기 직전 SQL
DB 오류 또는 실행 결과
로그에 기록된 문자열
```

단순히 “허용/거부”만 적지 않고 **어느 계층에서 문자열이 달라졌는지** 비교해야 의미가 있다.

### 2. alias 취약점의 패치 계보 비교

Django alias 검사는 한 번에 완성되지 않았다. 2025년과 2026년에 서로 다른 문자가 연이어 보강됐다.

| 취약점 | 추가로 문제가 된 문자·범위 | 분석 의미 |
|---|---|---|
| CVE-2025-59681 | MySQL·MariaDB의 `#` 주석 | DB별 주석 문법이 공통 정규식에서 빠질 수 있다. |
| CVE-2025-13372 | PostgreSQL alias의 `$` | 공통 검사 외에 backend compiler의 quoting도 중요하다. |
| CVE-2026-1287 | C0·C1 제어문자 전체 | 눈에 보이는 특수문자만 막아서는 계층별 해석 차이를 다루기 어렵다. |
| CVE-2026-1312 | alias의 마침표 `.` | 같은 alias가 `order_by()` 같은 다른 sink로 이동할 때 문법 의미가 달라진다. |

이 흐름을 따라가면 개별 payload 찾기보다 더 중요한 질문이 생긴다. 사용자 alias를 금지 문자 목록으로 계속 보완할 것인지, 항상 안전하게 quote하거나 허용 문자만 받도록 설계를 바꿀 것인지다.

## 참고 자료

- [GitHub Advisory — GHSA-gvg8-93h5-g6qq](https://github.com/advisories/GHSA-gvg8-93h5-g6qq)
- [Django 보안 공지 — 6.0.2, 5.2.11, 4.2.28](https://www.djangoproject.com/weblog/2026/feb/03/security-releases/)
- [Django 패치 커밋](https://github.com/django/django/commit/e891a84c7ef9962bfcc3b4685690219542f86a22)
- [Django 공식 문서 — Aggregation](https://docs.djangoproject.com/en/6.0/topics/db/aggregation/)
- [Django 공식 문서 — QuerySet API](https://docs.djangoproject.com/en/6.0/ref/models/querysets/)
- [PostgreSQL 공식 문서 — SQL lexical structure](https://www.postgresql.org/docs/current/sql-syntax-lexical.html)
- [PortSwigger — SQL Injection 필터 우회](https://portswigger.net/support/sql-injection-bypassing-common-filters)
- [MySQL 공식 문서 — String literals와 Control+Z](https://dev.mysql.com/doc/refman/8.0/en/string-literals.html)
- [CAPEC-52 — Embedding NULL Bytes](https://capec.mitre.org/data/definitions/52.html)
- [OWASP — Embedding Null Code](https://owasp.org/www-community/attacks/Embedding_Null_Code)
- [OWASP Logging Cheat Sheet — CR·LF 처리](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [GitHub Advisory — CVE-2025-59681](https://github.com/advisories/GHSA-hpr9-3m2g-3j9p)
- [GitHub Advisory — CVE-2025-13372](https://github.com/advisories/GHSA-rqw2-ghq9-44m7)
- [Django 보안 릴리스 목록 — CVE-2026-1312](https://docs.djangoproject.com/en/6.0/releases/security/)
