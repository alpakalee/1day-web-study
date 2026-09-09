# W11 · API test — BOLA — openwisp-ipam (GHSA-x287-5c68-36wp)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE 미부여 / 2026-08-26 / medium (CVSS 3.1 5.3) / openwisp-ipam (pip) `<= 1.2.0.post1`, first_patched_version 1.2.1
- 패치 커밋: https://github.com/openwisp/openwisp-ipam/commit/a4b272461bfa7a1762baf0b1fd76b4f5b681586b (PR #220, cherry-pick https://github.com/openwisp/openwisp-ipam/commit/04a2ef949498c6591f9ac35713d7451fb9f75362)
- diff 규모: +4/-2, 1파일 (`openwisp_ipam/admin.py`) + 테스트 +13/-0

## 왜 이 주차에 적절한가
advisory 본문이 취약점 유형을 직접 "broken object-level authorization"으로 명시하고, 정상 패턴(`ImportSubnetView.post()`가 `assert_organization_permissions(request)`로 조직 소속을 먼저 검증)과 취약 패턴(`ExportSubnetView.post()`가 그 검증 없이 바로 `Subnet.objects.get(pk=subnet_id)`로 진행)을 나란히 대조해 설명한다. BOLA 개념을 advisory가 스스로 정의하고 정상/취약 쌍을 제시해준다는 점에서, wger 사례(같은 파일 내 정상/취약 액션 대조)와 동일한 학습 구조를 API 뷰가 아닌 CWE-862 관점에서 한 번 더 보여준다.

다만 확인 결과 실제로 병합된 패치(PR #220, 커밋 a4b2724)는 advisory 본문이 지목한 `openwisp_ipam/api/views.py`의 `ExportSubnetView`가 아니라 **Django 관리자(admin) 사이트의 `SubnetAdmin.export_view()`**(`openwisp_ipam/admin.py`)를 고친 것이다. 패치는 `Subnet().export_csv(subnet_id, writer)` 호출 전에 `subnet = get_object_or_404(self.get_queryset(request), pk=subnet_id)`를 추가해 조직 스코프가 걸린 `get_queryset()`을 통과한 객체만 쓰도록 바꿨다 — 여기까지는 BOLA 수정의 정석(권한 필터가 걸린 쿼리셋으로 재조회)이라 교재로 쓰기 좋다. 현재 `master` 기준 `openwisp_ipam/api/views.py:305`의 `ExportSubnetView.post()`를 직접 확인한 결과 `self.subnet_model().export_csv(kwargs["subnet_id"], writer)`가 여전히 조직 필터 없이 남아 있어, advisory가 서술한 REST API 경로의 결함 자체는 이번 패치로 고쳐지지 않은 것으로 보인다(1.2.1 릴리즈에 admin 경로만 반영). 발표 시 "advisory 서술 = REST API, 실제 병합된 diff = Django admin"이라는 불일치를 명확히 짚고 넘어가야 한다.

## 취약점 한 줄 요약
(admin 패치 기준) URL 경로 파라미터 `subnet_id`가 조직 소속 필터 없이 바로 `Subnet.objects.get(pk=subnet_id)` 싱크에 들어가 다른 조직의 서브넷 이름·CIDR·전체 IP 목록을 CSV로 내려받을 수 있다. advisory가 지목한 REST API 경로(`ExportSubnetView`)는 동일한 구조적 결함이 코드상 아직 남아 있는 것으로 관찰된다(미확인 — 벤더 공식 확인 필요).

## 난이도·재현 메모
- diff 난이도(초심자 기준): 낮음. `Subnet().export_csv(subnet_id, writer)` → `get_object_or_404(self.get_queryset(request), pk=subnet_id)`로 재조회 후 `subnet.id`를 넘기는 3~4줄 변경이라 "조직 스코프 쿼리셋을 통과시켜야 한다"는 BOLA 수정 패턴이 명확히 보인다.
- 재현 환경 구축 부담: openwisp-ipam은 Django 앱(pip 설치 후 마이그레이션·조직 2개·유저 2명 세팅 필요)이라 wger와 비슷한 수준의 준비가 필요하다. advisory의 PoC 절차(OrgA/OrgB 두 조직 생성 → OrgB 유저로 OrgA 서브넷 export)를 그대로 따라가면 재현 가능.
- nuclei 템플릿 유무 / PoC 공개 여부: CVE가 없어 nuclei-templates 검색(`CVE-XXXX-XXXXX` 기반) 자체가 불가능. advisory 본문에 curl 수준의 PoC 절차(`POST /api/v1/subnet/{S}/export/`)가 서술돼 있으나, 이는 실제로 패치되지 않은 것으로 보이는 API 경로를 대상으로 한 서술이라 재현 시 admin 경로(`admin:ipam_export_subnet`)로 바꿔 따라가야 한다.

## 대안 후보
- GHSA-g8gc-6c4h-jg86 (wger, CVE-2026-27839, medium): 이미 이번 주 대표 후보로 채택됨. CVE 배정 + advisory 서술과 실제 패치 diff가 정확히 일치해 "advisory-diff 정합성" 면에서 이 openwisp-ipam 건보다 안전한 교재.
- GHSA-8c7q-86fq-vvmh (mlflow, CVE-2026-2651, critical): 인가 매핑 누락이라는 다른 결함 유형(broken authentication)으로, 이번 주 BOLA 주제와는 결이 다르지만 diff가 더 단순함.
- openwisp-ipam을 세 번째 보조 후보로 남긴 이유: "advisory가 BOLA를 스스로 정의해준다"는 장점은 확실하지만, advisory 서술과 실제 병합 diff의 대상 코드가 다르다는 결함이 있어 대표 후보보다는 "advisory 읽을 때 실제 코드와 대조 검증이 왜 필요한가"를 보여주는 심화/토론용 자료로 더 적합하다.
