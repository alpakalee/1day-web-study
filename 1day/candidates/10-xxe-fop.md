# W10 · XXE — apache xmlgraphics-fop (GHSA-jqfv-jrvq-95jm)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2024-28168 / 2024-10-09 / medium (CVSS 3.1 5.3) / org.apache.xmlgraphics:fop-core (maven), `<= 2.9`, first_patched_version 2.10
- 패치 커밋: https://github.com/apache/xmlgraphics-fop/commit/d96ba9a11710d02716b6f4f6107ebfa9ccec7134
- diff 규모: +2/-0, 1파일 (`fop-core/.../cli/InputHandler.java`)

## 왜 이 주차에 적절한가
`InputHandler.transformTo()`가 사용자가 지정한 XSLT를 적용하려고 `TransformerFactory.newInstance()`로 팩토리를 만든 뒤, 별도 보안 설정 없이 바로 `Transformer`를 생성했다. 패치는 팩토리 생성 직후 `factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)` 한 줄을 추가하는 것뿐이다. 이 feature는 XSLT stylesheet 처리 중 DTD·외부 엔티티 로드를 포함한 여러 안전장치를 한 번에 켜는 JAXP 표준 스위치라, "XML 관련 API는 파서든 트랜스포머든 기본값이 안전하지 않다"는 이번 주 XXE 주제의 핵심을 SAX/StAX 계열과 다른 API(XSLT Transformer)에서 다시 보여준다.

## 취약점 한 줄 요약
FOP 커맨드라인/라이브러리 호출 시 입력으로 주어진 XSLT stylesheet가 `TransformerFactory`/`Transformer` 싱크로 그대로 컴파일·적용되며, stylesheet 안에 심어진 DTD·외부 엔티티가 확장되어 서버 파일 읽기나 요청 기반 DoS로 이어진다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 매우 낮음. `setFeature` 한 줄 추가로 xwiki·wso2 사례와 형태가 동일해 세 후보를 나란히 보여주면 "API는 다르지만 방어 패턴은 항상 `setFeature`/`setProperty` 한두 줄"이라는 결론을 낼 수 있음.
- 재현 환경 구축 부담: FOP는 커맨드라인 PDF/XSL-FO 변환 도구(단일 jar 실행)라 톰캣 기반 xwiki, OSGi 기반 wso2보다 압도적으로 가볍다. `fop -xml input.xml -xsl evil.xsl -pdf out.pdf` 형태로 로컬에서 바로 재현 가능해 5인 스터디 발표용 셋업 부담이 가장 적음.
- nuclei 템플릿 유무 / PoC 공개 여부: nuclei-templates 검색 결과 0건. CLI 도구 특성상 네트워크 스캐너 대상이 아니라 nuclei 템플릿이 애초에 나오기 어려운 유형. PoC는 별도 공개본 없음 — 표준 XXE payload(외부 엔티티로 파일 읽기)를 XSLT stylesheet에 심으면 재현 가능.

## 대안 후보
- GHSA-gx4f-976g-7g6v (xwiki, CVE-2023-27480, high): 심각도가 더 높고 advisory PoC가 완결적이라 대표 후보로 채택. FOP는 재현 환경이 가장 가볍다는 점에서 "직접 손으로 돌려보는" 실습용 보조 후보로 적합.
- GHSA-fvfq-q238-j7j3 (wso2 carbon-mediation, CVE-2025-10713, medium): StAX 파서 사례로 fop(Transformer)와 API 계열이 달라 비교 학습에는 유용하나 재현 환경이 FOP보다 훨씬 무거움.
- fop을 보조 후보로 남긴 이유: 3개 후보 중 유일하게 실습 참가자가 개인 PC에서 직접 명령 한 줄로 재현해볼 수 있어, xwiki로 개념을 설명한 뒤 "직접 돌려보는" 데모용으로 가장 적합.
