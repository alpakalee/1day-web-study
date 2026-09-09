# W10 · XXE — wso2 carbon-mediation (GHSA-fvfq-q238-j7j3)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2025-10713 / 2025-11-05 / medium (CVSS 3.1 6.5) / org.wso2.carbon.mediation:org.wso2.carbon.localentry (maven), `< 4.7.259`, first_patched_version 미정
- 패치 커밋: https://github.com/wso2/carbon-mediation/commit/b995b2f1db96a4697791f0202cc8713f15640fd5
- diff 규모: +2/-0, 1파일 (`LocalEntryAdmin.java`)

## 왜 이 주차에 적절한가
`LocalEntryAdmin.nonCoalescingStringToOm()`이 관리자 콘솔에서 넘어온 XML 문자열을 `XMLInputFactory`로 파싱하면서 non-coalescing 옵션(`javax.xml.stream.isCoalescing=false`)만 설정하고 DTD·외부 엔티티 관련 속성은 그대로 기본값(허용)으로 뒀다. 패치는 같은 팩토리 인스턴스에 `xmlInFac.setProperty(XMLInputFactory.SUPPORT_DTD, Boolean.FALSE)`와 `xmlInFac.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.FALSE)` 두 줄을 추가하는 것뿐이다. xwiki(`DocumentBuilderFactory` + `disallow-doctype-decl`)와 파서 API(StAX `XMLInputFactory`)가 달라, 같은 XXE 개념이 자바 XML 파서마다 어떻게 다른 속성 이름으로 방어되는지 비교 사례로 쓰기 좋다.

## 취약점 한 줄 요약
관리 API로 전달된 local entry XML 문자열이 `XMLStreamReader`/`StAXOMBuilder` 싱크로 그대로 파싱되어, DTD 선언 안의 외부 엔티티가 확장되며 서버 파일 읽기·DoS(억검 엔티티 확장 등)로 이어진다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 낮음. 기존 코드에 `setProperty` 두 줄만 추가하는 구조라 "이 두 속성이 각각 DTD 자체 지원과 외부 엔티티 지원을 끈다"는 설명만 곁들이면 diff 자체는 직관적. 다만 xwiki 사례보다 상수 이름(`SUPPORT_DTD`, `IS_SUPPORTING_EXTERNAL_ENTITIES`)이 두 개라 방어 지점이 한 곳이 아니라는 점을 짚어줘야 함.
- 재현 환경 구축 부담: WSO2 Carbon 기반 미들웨어(ESB류) 자체가 OSGi 번들 다수로 구성된 대형 엔터프라이즈 스택이라 개인 PC에서 단기간에 빌드·구동하기는 xwiki보다도 부담이 큼. advisory에 공식 벤더 어드바이저리(WSO2-2025-4505) 외 별도 컨테이너 이미지 정보 없음.
- nuclei 템플릿 유무 / PoC 공개 여부: nuclei-templates 검색 결과 0건. PoC 코드는 advisory·벤더 어드바이저리 어디에도 공개되어 있지 않음 (일반적 XXE 공격 패턴 설명 수준).

## 대안 후보
- GHSA-gx4f-976g-7g6v (xwiki, CVE-2023-27480, high): 심각도가 더 높고 advisory에 완결된 PoC 절차가 있어 대표 후보로 채택됨. 이 wso2 건은 "같은 XXE라도 파서 API별로 방어 속성이 다르다"는 보조 설명용으로 남김.
- GHSA-jqfv-jrvq-95jm (apache fop, CVE-2024-28168, medium): `TransformerFactory` 기반이라 이 wso2 건과 마찬가지로 심각도는 낮지만, FOP는 재현 환경이 커맨드라인 PDF 변환기 수준이라 wso2보다 구축 부담이 훨씬 가벼움.
- wso2를 보조 후보로 남긴 이유: 서로 다른 자바 XML 파서(SAX/StAX/Transformer)의 방어 API를 3종 비교하는 슬라이드 구성 시 StAX 사례로 필요.
