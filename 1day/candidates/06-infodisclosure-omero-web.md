# W6 · 정보 탐색 — omero-web (GHSA-gpmg-4x4g-mr5r)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2025-54791 / 2025-08-13 / medium (CVSS3 5.3) / omero-web `<= 5.29.1`
- 패치 커밋: https://github.com/ome/omero-web/commit/8aa2789e8f759c73f1517abe9a0abd44e86644ad
- diff 규모: `omeroweb/webadmin/views.py` 1파일, +4/-5 (CHANGELOG.md 변경 제외)

## 왜 이 주차에 적절한가
패치 전 `forgotten_password` 뷰(`omeroweb/webadmin/views.py`)는 비밀번호 재설정 성공 시 `error = "Password was reset. Check your mailbox."`를 설정하지만, `omero.CmdError` 예외가 나면 `error = exp.err.parameters[exp.err.parameters.keys()[0]]`로 서버 내부 에러 파라미터를 그대로 화면에 노출했다. 이 파라미터에는 사용자/이메일 불일치 여부에 따라 다른 문구가 담겨, 응답 메시지 차이만으로 계정 존재 여부를 구분할 수 있다. PortSwigger information disclosure 랩 중 "다른 응답으로 사용자 열거(user enumeration via different responses)" 계열과 정확히 같은 패턴이라 초심자에게 "왜 상세 에러 메시지가 정보 노출인가"를 코드 수준에서 보여주기 좋다.

## 취약점 한 줄 요약
`ForgottonPasswordForm` POST 요청에서 사용자가 입력한 username/email이 `omero.cmd.ResetPasswordRequest`로 넘어가고, 그 처리 결과 예외의 내부 파라미터(`exp.err.parameters`)가 그대로 렌더링되는 `error` 컨텍스트 변수(싱크)로 흘러가 응답 페이지에 표시된다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 하. `try/except` 블록에서 예외 상세를 노출하던 것을 고정 문자열 `"Password was reset. Check your mailbox."`로 통일한 것뿐이라 5줄 diff만으로도 "성공/실패 메시지를 하나로 합쳤다"는 변경 의도가 바로 보인다.
- 재현 환경 구축 부담: 상. OMERO.web은 OMERO 서버(Java 백엔드) 전체 스택과 계정 DB가 필요해 로컬에 띄우기가 무겁다. 실습보다는 코드·diff 리딩 위주 발표에 적합.
- nuclei 템플릿 유무 / PoC 공개 여부: `gh api "/search/code?q=CVE-2025-54791+repo:projectdiscovery/nuclei-templates"` 결과 0건, nuclei 템플릿 없음. 별도 공개 PoC는 확인 안 함.

## 대안 후보
확인 안 함.
