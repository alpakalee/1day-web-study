# W5 · Business logic vulnerabilities — ethyca-fides (GHSA-qx5f-ghc2-7g5c)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2026-42303 / 2026-05-05 / Medium (CVSS4 6.1) / ethyca-fides `>= 2.75.0, < 2.83.2` (2.83.2에서 패치)
- 패치 커밋: ethyca/fides@e7a6527b0f9fdc9887b86a89bb5453e7421882dd (PR #7972)
- diff 규모: `RequestTableActions.tsx` +16/-3, `useApproveDenyPrivacyRequest.ts` +11/-1(패치 diff 상 확인분) — 합계 +15/-3(advisory 표기 기준), 2파일

## 왜 이 주차에 적절한가
- 취약 로직은 "중복(duplicate) 요청은 신원 검증을 건너뛰고 승인 버튼을 노출한다"는 가정 하나다. 패치 전 `useApproveDenyPrivacyRequest.ts`의 `showAction`은 `isPendingStatus || isDuplicateStatus`로, DUPLICATE 상태 요청이면 신원 검증(`identity_verified_at`) 여부와 무관하게 승인/거부 액션을 항상 노출했다. 패치는 `isUnverifiedDuplicate = isDuplicateStatus && !identity_verified_at && identityVerificationRequired`를 계산해 `showAction`과 `buttonVisibility.approve`에서 이 경우만 승인 버튼을 숨기도록 조건을 추가했다(`RequestTableActions.tsx`, `useApproveDenyPrivacyRequest.ts` 동일 패턴 중복).
- 공격 시나리오가 순수한 워크플로우 우회다: 공격자가 같은 이메일로 privacy request를 두 번 제출하고 OTP 인증을 끝까지 완료하지 않으면, 두 번째 요청이 "중복"으로 분류되어 관리자 화면에 나타난다. 관리자는 이 요청이 미검증 상태임을 인지하지 못한 채 통상적인 트리아지 과정에서 승인하고, 그 결과 신원 검증 없이 삭제(erasure) 요청이 처리된다 — PortSwigger의 "가정이 깨지는 지점(assumption)에서 발생하는 high-level logic flaw"와 정확히 대응한다.
- 30줄 diff 기준(2파일 +15/-3, 실질 코드 변경분만 보면 20여 줄)을 정확히 통과하는 몇 안 되는 business logic 후보다. 5주차는 CWE 태깅 특성상(CWE-841 Improper Enforcement of Behavioral Workflow처럼 로직 결함 전용 카테고리가 드묾) GHSA에서 발굴 가능한 후보 자체가 적은데, 이 건은 CWE-841이 정확히 붙어 있어 "워크플로우 검증 누락"이라는 주제를 GHSA 근거로 설명할 수 있는 사실상 유일한 사례다.

## 취약점 한 줄 요약
공격자가 제출한 두 번째(미검증) privacy request가 duplicate-detection에 의해 DUPLICATE 상태로 분류되면(입력), 관리자 UI가 `identity_verified_at` 미설정 여부를 확인하지 않고 승인 버튼(싱크: 승인 액션 → 삭제/접근 요청 처리 파이프라인)을 노출해 관리자가 미검증 요청을 그대로 승인할 수 있다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 두 파일 모두 "기존 조건식에 `isUnverifiedDuplicate` 불리언 하나를 AND/스프레드로 끼워 넣는" 동일한 수정 패턴이라 코드량 대비 이해는 쉽다. 다만 "duplicate detection이 무엇인지", "신원 검증(OTP)이 언제 완료되는지"라는 도메인 배경을 먼저 설명해야 diff가 왜 위험한지 와닿는다는 점이 부담이다.
- 재현 환경 구축 부담: Fides는 privacy request 처리용 백엔드+Admin UI+이메일(OTP) 연동이 필요한 무거운 애플리케이션이라, `subject_identity_verification_required`와 `privacy_request_duplicate_detection.enabled`를 모두 켠 상태로 엔드투엔드 재현하려면 별도 목업 환경 구성이 필요하다. 발표에서는 advisory의 스크린샷(관리자 승인 화면)과 diff 대조로 개념만 전달하는 편이 현실적이다.
- nuclei 템플릿 유무 / PoC 공개 여부: nuclei-templates 코드 검색을 GitHub API 레이트리밋으로 재확인하지 못했다(미확인) — 다만 CVE 공개 4개월 이내의 관리자 승인 트리아지형 로직 결함이라 nuclei 같은 무인증 스캐너 템플릿으로 다루기 어려운 유형(관리자 액션이 필요)이라 존재 가능성 자체가 낮다고 판단. advisory에 별도 공개 PoC 익스플로잇 코드는 없고, 공격 시나리오와 UI 스크린샷만 제공된다.

## 대안 후보
같은 주차 open-webui(GHSA-h3ww-q6xx-w7x3, high, +25/-6)는 "체크-사용 분리로 인한 레이스 컨디션"이라는 즉각 직관적인 그림을 보여주지만 diff가 기준선(30줄)을 살짝 초과하고 LDAP 서버/OAuth IdP 없이는 엔드투엔드 재현이 불가능하다. Fides 건은 severity가 medium으로 더 낮고 워크플로우 상태 머신(PENDING/DUPLICATE/AWAITING_PRE_APPROVAL 등) 배경 설명이 선행되어야 한다는 단점이 있지만, diff 규모가 기준을 여유 있게 통과하고 "체크 자체를 아예 안 한다"는 더 단순한 결함 형태라 발표 난이도 면에서는 open-webui보다 다루기 쉽다. taylored(레이스컨디션, 39줄, 아래 항목)는 별도로 기준 완화하여 포함시킨 세 번째 후보다.
