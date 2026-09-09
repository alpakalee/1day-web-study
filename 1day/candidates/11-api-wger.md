# W11 · API test — BOLA — wger (GHSA-g8gc-6c4h-jg86)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2026-27839 / 2026-02-26 / medium (CVSS 3.1 4.3) / wger (pip) <= 2.1, first_patched_version 미정
- 패치 커밋: https://github.com/wger-project/wger/commit/29876a1954fe959e4b58ef070170e81703dab60e
- diff 규모: +3/-3, 1파일 (`wger/nutrition/api/views.py`)

## 왜 이 주차에 적절한가
`NutritionPlanViewSet.nutritional_values`, `MealViewSet.nutritional_values`, `MealItemViewSet.nutritional_values` 세 액션이 각각 `NutritionPlan.objects.get(pk=pk)`, `Meal.objects.get(pk=pk)`, `MealItem.objects.get(pk=pk)`로 객체를 직접 조회한 뒤 `self.get_object()`(DRF가 뷰셋 쿼리셋 필터·object-level permission을 적용하는 경로)를 우회했다. 같은 파일의 `LogItemViewSet`은 `LogItem.objects.get(pk=pk, plan__user=self.request.user)`로 소유자 필터를 걸어 정상 처리하고 있어, 취약 지점과 정상 패턴이 한 파일 안에 나란히 존재한다 — PortSwigger API testing 랩의 핵심 개념인 "동일 엔드포인트 패턴에서 한 액션만 object-level 권한 체크 누락"을 그대로 보여준다. 패치는 세 곳 모두 `Model.objects.get(pk=pk)`를 `self.get_object()`로 바꾸는 것뿐이라 BOLA의 원인과 해법이 1:1로 대응된다.

## 취약점 한 줄 요약
URL 경로의 `pk`(사용자가 임의 지정 가능한 정수)가 소유자 검증 없이 바로 ORM `.get(pk=pk)` 싱크에 들어가 다른 사용자의 영양 플랜/식사/식품 항목 데이터를 반환한다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 매우 낮음. 세 줄 다 `X.objects.get(pk=pk)` → `self.get_object()` 치환뿐이라 diff만 봐도 "누가 이 pk를 소유했는지 확인 안 함"이 바로 보인다. DRF의 `get_object()`가 왜 안전한지(큐어리셋 필터 자동 적용)는 별도 설명이 필요하다.
- 재현 환경 구축 부담: wger는 Django 풀스택 앱(DB 마이그레이션, 초기 유저 생성 등) 구축 필요 — 스터디원이 개인 PC에서 15분 발표 전 준비하기엔 다소 무겁다. Docker compose로 공식 이미지가 제공되는지 확인 필요.
- nuclei 템플릿 유무 / PoC 공개 여부: advisory 본문에 PoC 스크립트(pk 1~100 순회) 포함, 별도 nuclei 템플릿은 미확인.

## 대안 후보
- GHSA-8c7q-86fq-vvmh / CVE-2026-2651 (mlflow, +3/-0 1파일, critical): 인증 체크 한 줄이 아예 빠진 교과서적 케이스로 더 단순하지만, "인증 자체 부재"라 이번 주 BOLA(인증된 사용자 간 권한 경계) 주제보다는 broken authentication 쪽에 가깝다.
- GHSA-x287-5c68-36wp (openwisp-ipam, +4/-2 1파일): advisory 본문이 "broken object-level authorization"을 직접 명시해 개념 대응은 명확하나 CVE 미배정이라 실제 영향도 비교·CVSS 근거 제시가 어렵다.
- wger 건을 채택한 이유: CVE 배정 + 동일 파일 내 정상/취약 패턴 대조가 가능해 "왜 이 한 줄이 문제인가"를 diff만으로 설명하기 가장 쉽다.
