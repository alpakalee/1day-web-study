# W8 · 파일 업로드 — kiwitcms (GHSA-2fqm-m4r2-fh98)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2023-33977 / 2023-06-06 / High (CVSS 8.1) / kiwitcms `<= 12.3` (12.4에서 패치)
- 패치 커밋: kiwitcms/Kiwi@d789f4b51025de4f8c747c037d02e1b0da80b034
- diff 규모: `tcms/kiwi_attachments/validators.py` +3/-0 한 파일. 같은 커밋에 테스트 파일(`tests/test_validators.py` +13/-0)과 PoC용 SVG 픽스처(`svg_with_onload_attribute.svg` +1/-0)가 함께 포함돼 있지만, 실제 검증 로직 변경은 3줄뿐이다.

## 왜 이 주차에 적절한가
- Kiwi TCMS는 첨부파일 업로드 시 `deny_uploads_containing_script_tag()`라는 validator로 파일 내용에 `<script` 문자열이 있는지만 청크 단위로 검사했다. SVG는 XML 기반 파일이라 `<script>` 태그 없이도 `<svg onload="...">` 같은 이벤트 핸들러 속성만으로 JS를 실행시킬 수 있는데, 패치 전 코드는 이 경로를 전혀 걸러내지 않았다.
- 패치는 동일 함수에 `if chunk.lower().find(b"onload=") > -1: raise ValidationError(...)` 세 줄만 추가해 온로드 속성 업로드를 차단한다. 확장자 자체는 애초에 허용 대상(SVG)이라 "확장자 검증"이 아니라 "허용된 파일 타입 내부의 콘텐츠 검증 누락"이라는, 이번 주 파일 업로드 주제 중에서도 조금 다른 각도(콘텐츠 기반 저장형 XSS)를 보여주기 좋다.
- CWE-434(Unrestricted Upload) 라벨이 붙어 있지만 실제로는 CWE-79(Stored XSS)에 더 가깝다. "업로드 자체는 막을 필요 없는 확장자인데, 파일 내용 검증이 블랙리스트 방식이라 우회됐다"는 점을 짚어주면 이번 주 다른 후보(확장자 우회)와 대비되는 사례로 쓸 수 있다.

## 취약점 한 줄 요약
XML-RPC `User.add_attachment`로 올라온 SVG 파일 바이트(입력)가 `deny_uploads_containing_script_tag()` validator에서 `<script` 문자열만 검사받고 그대로 통과해 첨부파일 스토리지(싱크)에 저장된 뒤, 브라우저가 이를 열람할 때 `onload` 속성의 JS가 실행된다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 매우 쉽다. `chunk.lower().find(b"<script")`와 `chunk.lower().find(b"onload=")` 두 줄을 나란히 보여주면 "블랙리스트 검사 항목이 부족했다"는 원인을 1분 안에 설명할 수 있다. 다만 diff 자체는 짧아서 "왜 SVG가 위험한 파일 타입인가"(XML 기반이라 스크립트 태그 없이도 이벤트 핸들러로 JS 실행 가능)를 발표자가 별도로 설명해야 전달력이 생긴다.
- 재현 환경 구축 부담: Kiwi TCMS는 Django 기반 앱으로 DB(MariaDB/PostgreSQL) 등 의존성이 있어 로컬에 단독 Flask 스크립트로 재현하기는 어렵다. Docker Compose로 전체 스택을 띄워야 XML-RPC 첨부파일 업로드 경로까지 재현 가능해 다른 후보보다 환경 구축 부담이 크다.
- nuclei 템플릿 유무 / PoC 공개 여부: `projectdiscovery/nuclei-templates`에서 CVE-2023-33977 검색 결과 0건. advisory 본문에 PoC 코드는 없고, 패치 커밋에 포함된 `svg_with_onload_attribute.svg` 테스트 픽스처가 사실상 최소 PoC 역할을 한다.

## 대안 후보
open-webui 업로드→RCE 건(GHSA-ff5c-56m7-vc75 / CVE-2024-8060, +21/-6, 파일 1개)은 diff는 더 크지만 업로드가 임의 파일 쓰기로 이어지는 임팩트가 훨씬 강렬하고, 로컬 재현(Flask 앱 하나로 가능한 수준은 아니지만 Docker 이미지 하나로 가능)도 Kiwi TCMS 전체 스택보다는 가볍다. kiwitcms 건은 diff가 가장 짧고 "블랙리스트 검증 항목 누락"이라는 개념을 명확히 보여주지만, Django+DB 스택을 띄워야 하는 재현 부담과 SVG XSS라는 다소 결이 다른 주제(확장자 자체보다 콘텐츠 검증) 때문에 대안으로 남겨두고, 이번 주 메인 후보로는 재현이 쉬운 Flask-Reuploaded 건을 우선 채택했다.
