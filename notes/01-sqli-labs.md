# PortSwigger SQL Injection Lab 지도

> 기준: 2026-09-14 PortSwigger SQL injection learning path  
> 목적: 정답 목록이 아니라, 각 Lab에서 연습할 사고 과정을 미리 보여 주는 학습 지도

- [SQL injection 전체 Lab](https://portswigger.net/web-security/all-labs#sql-injection)
- [SQL injection learning path](https://portswigger.net/web-security/learning-paths/sql-injection)

## 전체 지도

```text
조건 변경
  ├─ 숨겨진 데이터
  └─ 로그인 우회
        ↓
UNION
  ├─ 열 개수
  ├─ 문자열 열
  ├─ 다른 테이블
  └─ 한 열에 여러 값
        ↓
DB 조사
  ├─ DB 종류·버전
  └─ 테이블·열 목록
        ↓
Blind
  ├─ 조건부 응답
  ├─ 조건부 오류
  ├─ 보이는 오류
  ├─ 시간 지연
  └─ Out-of-band
        ↓
다른 입력 형식과 필터 우회
```

## 1단계 — SQLi의 구조 익히기

| 순서 | PortSwigger Lab | 난이도 | 무엇을 배울까? |
|---|---|---|---|
| 1 | SQL injection vulnerability in `WHERE` clause allowing retrieval of hidden data | Apprentice | 입력으로 기존 필터 조건을 바꾸고 뒤쪽 조건을 정리한다. |
| 2 | SQL injection vulnerability allowing login bypass | Apprentice | 사용자명 입력이 인증 쿼리의 비밀번호 조건을 어떻게 제거하는지 이해한다. |

### 완료 기준

```text
□ 원래 SQL을 추정할 수 있다.
□ 입력을 [문맥 닫기 / 의미 변경 / 뒤쪽 정리]로 나눌 수 있다.
□ 공격 전후의 조건식을 비교할 수 있다.
```

발표 시간에는 이 두 문제를 우선 사용한다.

## 2단계 — UNION으로 결과 모양 맞추기

| 순서 | PortSwigger Lab | 난이도 | 무엇을 배울까? |
|---|---|---|---|
| 3 | SQL injection UNION attack, determining the number of columns returned by the query | Practitioner | 원래 결과의 열 개수를 응답 차이로 추론한다. |
| 4 | SQL injection UNION attack, finding a column containing text | Practitioner | 각 열의 자료형과 실제 출력 위치를 구분한다. |
| 5 | SQL injection UNION attack, retrieving data from other tables | Practitioner | 열 개수와 자료형을 맞춰 다른 테이블의 결과를 합친다. |
| 6 | SQL injection UNION attack, retrieving multiple values in a single column | Practitioner | 출력 가능한 열이 부족할 때 여러 문자열을 연결한다. |

### 완료 기준

```text
열 개수 → 문자열 호환 열 → 출력되는 열 → 목표 데이터
```

- `NULL`을 자리 채우기로 쓰는 이유를 설명할 수 있다.
- 열 개수는 맞는데 실패할 때 자료형을 의심할 수 있다.
- 문자열 연결 문법이 DB마다 다름을 알고 치트시트를 찾을 수 있다.

## 3단계 — DB의 정체와 구조 알아내기

| 순서 | PortSwigger Lab | 난이도 | 무엇을 배울까? |
|---|---|---|---|
| 7 | SQL injection attack, querying the database type and version on MySQL and Microsoft | Practitioner | DB별 버전 표현식으로 DBMS를 식별한다. |
| 8 | SQL injection attack, listing the database contents on non-Oracle databases | Practitioner | `information_schema`에서 테이블과 열을 찾은 뒤 목표 데이터를 조회한다. |

### 완료 기준

```text
DB 종류 확인
    ↓
테이블 목록 확인
    ↓
관심 테이블의 열 확인
    ↓
목표 데이터 조회
```

CTF에서 `users`라는 테이블 이름이 주어지지 않아도 다음 단계로 갈 수 있어야 한다.

## 4단계 — 결과가 직접 보이지 않는 Blind SQLi

| 순서 | PortSwigger Lab | 난이도 | 관찰 채널 | 무엇을 배울까? |
|---|---|---|---|---|
| 9 | Blind SQL injection with conditional responses | Practitioner | 화면 내용 | 참/거짓에 따른 문구 차이로 값을 한 글자씩 추론한다. |
| 10 | Blind SQL injection with conditional errors | Practitioner | 오류 여부 | 조건이 참일 때만 오류를 발생시켜 1비트의 정보를 얻는다. |
| 11 | Visible error-based SQL injection | Practitioner | 오류 메시지 | 자료형 변환 등의 오류 메시지에 목표 값을 노출시킨다. |
| 12 | Blind SQL injection with time delays and information retrieval | Practitioner | 응답 시간 | 조건부 지연으로 참/거짓을 구분하고 값을 복원한다. |

### Blind 문제의 공통 구조

```text
알고 싶은 사실을 예/아니오 질문으로 바꿈
              ↓
서버에서 참과 거짓을 구분할 신호 선택
              ↓
한 글자 또는 한 범위씩 반복
              ↓
전체 값 복원
```

시간 기반에서는 한 번 느렸다는 사실만으로 결론 내리지 않는다. 네트워크 지연과 구분할 수 있도록 참 조건과 거짓 조건을 비교하고 반복 관찰한다.

## 5단계 — Out-of-band와 다른 입력 형식

| 순서 | PortSwigger Lab | 난이도 | 무엇을 배울까? |
|---|---|---|---|
| 13 | Blind SQL injection with out-of-band interaction | Practitioner | 웹 응답이 아무 신호도 주지 않을 때 DB의 외부 상호작용으로 실행 여부를 확인한다. |
| 14 | Blind SQL injection with out-of-band data exfiltration | Practitioner | 외부 요청에 데이터 일부를 포함해 직접 전달하는 개념을 이해한다. |
| 15 | SQL injection with filter bypass via XML encoding | Practitioner | HTTP 파라미터뿐 아니라 XML 내부 값도 입력 지점이며, 디코딩 순서가 필터와 DB 해석의 차이를 만들 수 있음을 배운다. |

OAST 문제는 SQL 초급 발표의 필수 실습이 아니다. “화면·오류·시간에도 차이가 없다면 별도의 관찰 채널이 필요하다”는 최종 분기로 이해하면 충분하다.

## 발표용 추천 문제

40분 안에는 모든 Lab을 풀 수 없다. 다음처럼 역할을 나눈다.

| 구분 | Lab | 사용 방법 |
|---|---|---|
| 함께 풀이 | Hidden data | SQL 문장이 변하는 과정을 그림으로 설명한다. |
| 함께 풀이 | Login bypass | 수강자가 페이로드를 세 조각으로 해체한다. |
| 개념 문제 | UNION column count | `NULL` 칸을 늘리는 그림으로 열 개수를 추론한다. |
| 마무리 문제 | Conditional responses | 참/거짓 응답으로 비밀값을 좁히는 원리를 묻는다. |
