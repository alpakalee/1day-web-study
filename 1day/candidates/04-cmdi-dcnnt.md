# W4 · OS Command injection — dcnnt-py (GHSA-8p42-7597-p2f6)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2023-1000 / 2024-04-27 / Medium (CVSS 6.3) / dcnnt `<= 0.9.0` (0.9.1에서 패치)
- 패치 커밋: cyanomiko/dcnnt-py@b4021d784a97e25151a5353aa763a741e9a148f5
- diff 규모: `dcnnt/plugins/notifications.py` +2/-1, 1파일

## 왜 이 주차에 적절한가
- 패치 diff 자체가 취약점을 요약한다: `command = cmd.format(uin=uin, name=name, icon=icon, text=text, title=title, package=package)`였던 문자열 조립을 `command = cmd.format(uin=quote(uin), name=quote(name), ...)`로 바꾸고 `subprocess.call(command, shell=True)`는 그대로 두었다 — 즉 싱크(`shell=True` 호출)는 안전하지 않은 채 각 필드를 `shlex.quote()`로 이스케이프하는 것만으로 막혔다.
- 사용자 정의 알림 명령 템플릿(`cmd`)에 클라이언트가 보낸 필드(uin/name/text/title 등)를 그대로 꽂아 넣는 구조라 PortSwigger가 강조하는 "셸 메타문자(`;`, `` ` ``, `$()`)를 이스케이프하지 않고 문자열 삽입"이라는 개념과 정확히 대응한다. 커밋 메시지도 "All text received over the network MUST be escaped before being transmitted to ... the shell command arguments"라고 원인을 명시한다.

## 취약점 한 줄 요약
네트워크로 수신한 알림 필드(uin, name, text, title, package 등)가 이스케이프 없이 `cmd.format(...)`으로 셸 명령 문자열에 삽입되고, 그 문자열이 `subprocess.call(command, shell=True)`(싱크)로 그대로 실행된다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 3줄짜리 diff. `.format()` 문자열 조립 → `shell=True` 실행이라는 한 줄짜리 인과관계만 보면 되어 5개 후보 중 가장 짧고 직관적이다.
- 재현 환경 구축 부담: dcnnt는 단일 파이썬 서버(알림 릴레이 데몬)라 pip 설치 후 로컬에서 바로 클라이언트-서버 통신을 흉내 낼 수 있어 부담이 적다. 다만 프로토콜(uin 인증, 페어링) 문서화가 부실해 정확한 요청 포맷을 맞추는 데는 advisory/PR #23 확인이 필요하다.
- nuclei 템플릿 유무 / PoC 공개 여부: `projectdiscovery/nuclei-templates` 코드 검색 결과 CVE-2023-1000 매칭 0건. 공개 PoC 익스플로잇은 advisory에 별도로 없음(VulDB 참조만 존재).

## 대안 후보
같은 주차의 llamafactory(GHSA-hj3w-wrh4-44vp)·mlflow(GHSA-rvhj-8chj-8v3c)는 둘 다 f-string으로 명령 문자열을 만든 뒤 `shell=True`로 실행하는 동일 패턴이라 구조는 유사하지만, dcnnt는 필드가 5개(uin/name/icon/text/title/package)라 "어느 필드가 메타문자 주입 지점인가"를 고르는 연습이 가능해 다른 두 후보(단일 변수 삽입)보다 발표에서 다룰 변주가 더 많다. severity는 medium으로 셋 중 가장 낮지만, 초심자 난이도와 재현 부담이 가장 낮다는 점에서 입문용으로 채택했다.
