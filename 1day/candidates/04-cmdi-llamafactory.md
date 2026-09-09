# W4 · OS Command injection — llamafactory (GHSA-hj3w-wrh4-44vp)

- CVE / 공개일 / 심각도 / 패키지·영향 버전: CVE-2024-52803 / 2024-11-21 / High (CVSS 7.5) / llamafactory `<= 0.9.0` (0.9.1에서 패치)
- 패치 커밋: hiyouga/LLaMA-Factory@b3aa80d54a67da45e9e237e349486fb9c162b2ac
- diff 규모: `src/llamafactory/webui/runner.py` +1/-1, 1파일

## 왜 이 주차에 적절한가
- 취약 코드는 `self.trainer = Popen(f"llamafactory-cli train {save_cmd(args)}", env=env, shell=True)` 한 줄이다. `save_cmd(args)`는 웹UI에서 사용자가 입력한 학습 설정값(`output_dir` 등)을 명령줄 인자 문자열로 직렬화한 결과이며, 이 문자열이 f-string으로 명령 전체에 삽입된 뒤 `shell=True`로 실행된다. 패치는 `Popen(["llamafactory-cli", "train", save_cmd(args)], env=env)`로 바꿔 문자열 조립 자체를 제거하고 `shell=True`도 함께 없앴다.
- PortSwigger 문서가 "shell=True로 사용자 입력을 문자열째 넘기는 것"을 가장 흔한 실수로 꼽는데, 이 CVE는 웹UI(Gradio) → 학습 파라미터 → 서버 셸 실행이라는 짧고 명확한 데이터 흐름이라 초심자에게 "왜 리스트 인자 대신 문자열+shell=True가 위험한가"를 바로 보여주기 좋다.
- 공개 PoC 스크립트(advisory 내 gist 링크)와 GIF 시연이 존재해 공격 표면을 말로 설명하지 않고 바로 재현 그림으로 보여줄 수 있다.

## 취약점 한 줄 요약
Gradio 웹UI에서 사용자가 입력한 학습 인자(`output_dir` 등, `save_cmd(args)`로 직렬화)가 `Popen(f"llamafactory-cli train {save_cmd(args)}", shell=True)`(싱크)에 그대로 삽입되어 셸에서 실행된다.

## 난이도·재현 메모
- diff 난이도(초심자 기준): 1줄 수정. "f-string 삽입 + shell=True" 대 "리스트 인자 + shell 제거"라는 명확한 대조라 커맨드 인젝션의 표준 수정 패턴을 그대로 보여준다.
- 재현 환경 구축 부담: LLaMA-Factory 자체가 GPU/대용량 모델을 전제로 하는 학습 프레임워크라 풀 스택 배포는 무겁다. 다만 advisory의 PoC는 `output_dir` 등 폼 필드만 조작해 웹UI 프로세스를 띄우는 수준에서 트리거되므로, GPU 없이도 웹서버만 기동하면 개념 재현은 가능할 수 있음(사전 검증 필요).
- nuclei 템플릿 유무 / PoC 공개 여부: `projectdiscovery/nuclei-templates` 코드 검색 결과 CVE-2024-52803 매칭 0건. advisory에 PoC 익스플로잇 스크립트(gist)와 시연 GIF가 공개되어 있어 재현 난이도는 낮은 편.

## 대안 후보
mlflow(GHSA-rvhj-8chj-8v3c)와 거의 동일한 "f-string + shell=True" 패턴이지만 mlflow는 critical/CVSS 9.6으로 임팩트가 더 크고 diff에 `shlex.quote()`라는 표준 수정법이 등장해 대조 예시로 쓰기 좋다. llamafactory는 그 대신 "애초에 shell=True/문자열 조립을 없앤" 더 근본적인 수정 방향(리스트 인자화)을 보여주므로, 두 건을 나란히 놓으면 "이스케이프 vs 애초에 셸을 안 쓰는 것"이라는 두 가지 방어 전략을 대비시킬 수 있어 함께 채택했다.
