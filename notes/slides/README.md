# SQL Injection Excalidraw 슬라이드 원본

`excalidraw/` 아래 파일은 각 장을 독립적으로 편집할 수 있는 Excalidraw 원본이다.
`assets/` 아래에는 발표 자료에 바로 삽입할 수 있는 SVG가 있다.

| 장 | 파일 | 발표 메시지 |
|---|---|---|
| 1 | `01-sqli-big-picture.excalidraw` | 입력 → 서버 → DB → 응답의 전체 흐름 |
| 2 | `02-sql-as-a-question.excalidraw` | SQL은 데이터베이스에 보내는 질문 |
| 3 | `03-login-flow.excalidraw` | 로그인 폼 뒤의 처리 과정 |
| 4 | `04-injection-boundary.excalidraw` | 값과 SQL 구조의 경계가 무너지는 순간 |
| 5 | `05-payload-anatomy.excalidraw` | 문맥 닫기 + SQL 삽입 + 뒤쪽 정리 |
| 6 | `06-three-axes.excalidraw` | 입력 문맥 + 결과 채널 + 현재 목표 |
| 7 | `07-union-shape.excalidraw` | UNION의 열 개수와 자료형 |
| 8 | `08-blind-channel.excalidraw` | Blind SQLi의 예/아니오 추론 |
| 9 | `09-exploitation-path.excalidraw` | 발견부터 영향 판단까지의 전체 경로 |
| 10 | `10-prepared-statement.excalidraw` | SQL 구조와 입력값 분리 |

## 편집 방법

1. Excalidraw에서 원하는 `.excalidraw` 파일을 연다.
2. 발표 환경에 맞게 글자 크기와 위치를 조정한다.
3. 완성본을 SVG로 내보낸다.
4. SVG는 `notes/slides/assets/`에 같은 이름으로 저장한다.

온라인 편집기에 올리고 싶지 않다면 Excalidraw Desktop/PWA 또는 VS Code의 Excalidraw 확장을 사용할 수 있다.

## 다시 생성하기

```powershell
node tools\generate-sqli-excalidraw.mjs
node tools\export-excalidraw-svg.mjs
```

위 명령은 `excalidraw/`의 10개 원본을 다시 생성하므로, Excalidraw에서 직접 수정한 뒤에는 실행하지 않는다. 직접 수정본을 보존하려면 먼저 Git에 커밋하거나 다른 이름으로 저장한다.
