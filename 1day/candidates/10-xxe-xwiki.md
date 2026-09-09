# W10 · XXE — xwiki-platform-xar-model (GHSA-gx4f-976g-7g6v)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2023-27480 / 2023-03-08 / high (CVSS 3.1 7.7) / org.xwiki.platform:xwiki-platform-xar-model (maven), `>=1.1-milestone-3, <13.10.11` 등 3개 구간
- 패치 커밋: https://github.com/xwiki/xwiki-platform/commit/e3527b98fdd8dc8179c24dc55e662b2c55199434
- diff 규모: +2/-0, 1파일 (`xwiki-platform-core/.../xar/XarPackage.java`)

## 왜 이 주차에 적절한가
`XarPackage.readDescriptor()`가 사용자가 업로드한 XAR(zip) 안의 `package.xml`을 `DocumentBuilderFactory`로 파싱하면서 `disallow-doctype-decl` feature를 켜지 않았다. 패치는 `dBuilder = dbFactory.newDocumentBuilder()` 호출 직전에 `dbFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` 딱 한 줄을 추가하는 것뿐이다. PortSwigger XXE 랩의 첫 방어 원칙이 "DOCTYPE 선언 자체를 차단하라"인데, 이 CVE는 그 원칙이 왜 최우선인지(feature 하나만 켜면 외부 엔티티 확장·SSRF·파일 읽기 경로가 통째로 막힘)를 실제 프로덕션 코드로 보여준다.

## 취약점 한 줄 요약
편집 권한이 있는 사용자가 첨부파일로 올린 XAR 안의 `package.xml`(`<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>`)이 `DocumentBuilder.parse()` 싱크에 그대로 들어가 XAR import 미리보기 화면(`?sheet=XWiki.AdminImportSheet&file=...`)에 서버 파일 내용이 렌더링된다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 매우 낮음. `setFeature` 한 줄 추가가 전부라 "DOCTYPE 자체를 막는다"는 개념과 코드가 1:1로 대응. 다만 자바 문법 자체(팀원 전원이 pip 기준으로 준비해온 스터디)에는 익숙하지 않을 수 있음 — 그래도 `DocumentBuilderFactory`, `setFeature`, `disallow-doctype-decl` 같은 API 이름이 그대로 의미를 드러내서 자바를 몰라도 diff만으로 원인·해법을 따라가기는 쉬운 편.
- 재현 환경 구축 부담: XWiki는 톰캣+DB 기반 풀스택 위키 엔진이라 개인 PC에서 15분 발표 전에 띄우기엔 무거움. 공식 Docker 이미지(`xwiki/xwiki`)가 있어 도커로는 가능하나, XAR 파일 조작·첨부·시트 URL 호출까지 시나리오가 여러 단계라 wger BOLA류보다 재현 스텝이 길다.
- nuclei 템플릿 유무 / PoC 공개 여부: nuclei-templates 저장소에 CVE-2023-27480 검색 결과 0건. advisory 본문에 forged XAR + `package.xml` PoC 절차가 상세히 포함되어 있어 별도 PoC 스크립트 없이도 재현 가능.

## 대안 후보
- GHSA-fvfq-q238-j7j3 (wso2 carbon-mediation, CVE-2025-10713, medium): `XMLInputFactory` 속성 2개 미설정으로 xwiki보다 진입점(로컬 엔트리 관리 API)이 더 좁고 실습용 빌드가 더 무거워 보조 후보로 남김.
- GHSA-jqfv-jrvq-95jm (apache fop, CVE-2024-28168, medium): `TransformerFactory`의 `FEATURE_SECURE_PROCESSING` 누락 사례로 개념적으로는 xwiki와 유사하나 CVSS·심각도가 더 낮고 XSLT 처리 경로라 XXE 개념 설명에는 한 단계 우회가 더 필요함.
- xwiki를 대표 후보로 채택한 이유: high 심각도 + `disallow-doctype-decl` 미설정이라는 "가장 정석적인" XXE 방어 실패 패턴 + advisory 자체에 완결된 PoC 절차가 있어 대표작으로 가장 설명하기 쉽다.
