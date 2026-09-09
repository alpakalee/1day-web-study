# W9 · SSRF — mobsf (GHSA-m435-9v6r-v5f6)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2024-54000 / 2025-06-27(github_reviewed_at, nvd_published_at는 2024-12-03) / High (CVSS 7.5) / mobsf `< 3.9.7`
- 패치 커밋: MobSF/Mobile-Security-Framework-MobSF@f22c584aa7d43527970c9da61eb678953cfc0a8e
- diff 규모: `mobsf/StaticAnalyzer/views/android/manifest_analysis.py` +4/-1 한 파일.

## 왜 이 주차에 적절한가
- MobSF는 안드로이드 앱의 App Links(`assetlinks.json`) 검증을 위해 매니페스트에 적힌 URL로 직접 HTTP 요청을 보낸다(`_check_url(host, w_url)`). 이전에 한 번 SSRF가 리포트돼 URL 자체는 검증했지만, 실제 요청 호출부 `requests.get(w_url, allow_redirects=True, ...)`가 리다이렉트를 자동으로 따라가도록 남아 있었다. 공격자가 자신의 도메인에서 302로 내부망 주소(`http://192.168.1.102/...`)로 리다이렉트시키면 검증을 통과한 뒤 실제 요청은 내부망으로 간다.
- 패치는 `allow_redirects=False`로 바꾸고, `status_code == 302`일 때 `status = False` 처리를 추가해 리다이렉트 자체를 차단한다. PortSwigger SSRF 랩의 "블랙리스트/화이트리스트 기반 필터를 오픈 리다이렉트로 우회"라는 개념과 원인·구조가 거의 동일해, 이번 주 대표 사례로 삼기 좋다.
- diff가 requests 호출 한 곳의 파라미터 변경과 상태코드 분기 추가뿐이라, "검증 시점과 실제 요청 시점이 분리되면 왜 위험한가"를 화면 하나로 설명할 수 있다.

## 취약점 한 줄 요약
매니페스트에서 추출한 App Links 호스트/URL(입력)이 `_check_url()`의 `requests.get(w_url, allow_redirects=True)`(싱크)로 그대로 전달돼, 외부에서 통제한 302 응답이 내부망 리소스로의 실제 요청을 유발한다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 매우 쉬움. `allow_redirects=True → False` 한 단어 변경과 302 분기 추가만 보여주면 되고, "리다이렉트를 자동으로 따라가면 검증이 무의미해진다"는 설명도 짧게 끝난다.
- 재현 환경 구축 부담: MobSF 전체를 띄우고 조작된 매니페스트가 포함된 APK를 정적 분석시켜야 이 경로를 재현할 수 있어, 단순 curl/Flask 스크립트로 끝나는 다른 SSRF 후보보다 준비물이 많다(APK 빌드 또는 샘플 APK 확보 필요).
- nuclei 템플릿 유무 / PoC 공개 여부: `projectdiscovery/nuclei-templates`에서 CVE-2024-54000 검색 결과 0건. advisory 본문에 개념 증명 스크린샷은 있으나 완성된 PoC 코드는 없다.

## 대안 후보
weasyprint 건(GHSA-983w-rhvv-gwmv)은 같은 "검증 후 리다이렉트로 우회" 패턴이지만 PDF 렌더링 라이브러리라는 조금 더 일반적인 웹 서버 상황에서 재현하기 쉽고, vllm 건(GHSA-v359-jj2v-j536)은 리다이렉트가 아니라 URL 파서 불일치라는 다른 우회 기법을 보여준다. mobsf 건은 diff가 가장 짧고 PortSwigger 랩과 구조가 가장 가깝지만, 재현에 APK/매니페스트 조작이 필요해 준비 부담이 있다는 점을 감안해 weasyprint 건과 함께 병행 후보로 제시한다.
