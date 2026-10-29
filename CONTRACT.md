# CTF Auto Harness — AI Agent 계약서

## 핵심 원칙

이 계약서는 `hacking_harness/AGENTS.md`의 CTF 확장판입니다.

**AI 출력은 Evidence가 아니다.**
- Tool Observation (실제 명령 실행 결과)만 증거
- AI의 추정/분석은 INFERENCE로 명시
- 자동 실행도 증거 로깅 필수

---

## 안전성 범위 (CTF 원칙)

### ✅ 절대 허용 (Safe)

```
- 로컬호스트 (127.0.0.1, localhost)
- 사용자가 setup한 격리 환경 (Docker, VM)
- 대회 제공 IP (명시적으로 대회 범위라고 언급된 경우)
```

### ⚠️ 조건부 허용 (Caution)

이들은 **매우 제한적으로만** 실행됨:

```
- 포트 스캔: nmap만, -sT (연결 스캔) 제한, 너무 많은 포트 동시 스캔 금지
- 서비스 열거: 기본 요청만 (HTTP GET, FTP LIST), 반복 X
- 취약점 테스트: 각 payload당 1회 시도만, 같은 것 반복 금지
- SQL injection: Union/Time-based 기본만, 무차별 데이터 추출 금지
```

### ❌ 절대 금지 (Blacklist)

이들 중 하나라도 요청되면 AI가 **즉시 거절**:

```
[1] 브루트포스 (Brute Force)
    ❌ 비밀번호 추측: hydra, John, hashcat 무제한
    ❌ 디렉토리 추측: gobuster, wfuzz 무차별
    ❌ 사용자명 열거: 수천 개 시도
    이유: 서버 응답 시간 초과, DoS 유발 가능

[2] DoS / DDoS
    ❌ 느린 HTTP 공격 (Slowloris)
    ❌ 대량 요청 flooding (ab, wrk 악용)
    ❌ 리소스 고갈 (CPU, 메모리, 연결)
    이유: 대회에서 서비스 중단 = 실격

[3] 무제한 자동 스캔
    ❌ Nuclei 풀 스캔 (모든 템플릿)
    ❌ Burp Pro 자동 공격
    ❌ Nessus 종합 스캔
    이유: 브루트포스로 귀결, 오탐 많음

[4] 데이터 파괴/변조
    ❌ DELETE 쿼리, DROP 테이블
    ❌ 파일 삭제, 설정 변경
    ❌ 사용자 계정 잠금
    이유: 대회 규칙 위반, 실격

[5] 지속성 / Backdoor
    ❌ 웹셸 업로드
    ❌ cron job 설치
    ❌ Reverse shell 연결
    ❌ SSH 키 배포
    이유: 대회 규칙 위반, 보안 사고

[6] 민감 정보 수집 후 악용
    ❌ 추출한 비밀번호로 다른 서비스 접근
    ❌ 개인정보 판매/유포
    ❌ 신용카드 데이터 탈취
    이유: 범죄, 윤리 위반

[7] 무한 루프 / 자원 소모
    ❌ 타임아웃 없는 반복 명령
    ❌ 재귀적 요청
    ❌ 메모리 누수 유발
    이유: 프로세스 hang, 리소스 고갈
```

---

## 반자동 실행 흐름 (Semi-Automation)

### 단계 1: 정찰 (Reconnaissance) — 자동 실행 가능

```
IP 입력
  ↓
[AI] nmap, service version scan 자동 실행
  ↓
결과 표시 (열린 포트, 서비스, 버전)
  ↓
다음 단계로
```

**규칙**:
- nmap만 사용 (`-sT` 커넥션 스캔, 상위 1000개 포트)
- 반복 금지 (같은 대상 다시 스캔 안 함)
- 타임아웃 설정 (최대 60초)

---

### 단계 2: 공격 제안 (Advisor) — 사용자 승인 필수

```
[AI] 발견된 서비스별로 가능한 공격 제안
  ↓
┌─────────────────────────────────────────┐
│ 추천 공격 (위험도 낮은 것부터)            │
├─────────────────────────────────────────┤
│ [1] Apache 헤더 분석        🟢 LOW       │
│ [2] MySQL 기본 자격증명     🟡 MEDIUM    │
│ [3] SQL Injection (기본)    🔴 HIGH      │
├─────────────────────────────────────────┤
│ >>> [사용자 입력 필수]                   │
│     go / select / skip / custom          │
└─────────────────────────────────────────┘
  ↓
[사용자] go (포괄 승인) / select 1,3,5 / skip / custom
```

**규칙**:
- 각 공격마다 위험도, 성공률, 설명 표시
- 사용자가 명시적으로 승인할 때까지 실행 안 함
- "go"라고 하면 제안된 공격들만 순차 실행 (Blacklist 공격은 제외)

---

### 단계 3: 공격 실행 (Executor) — 포괄 승인 후 자동

```
[사용자] go

→ [AI] 각 공격 순차 실행 (병렬 X)
  │
  ├─ [공격1] Apache 헤더... ✓ (3초)
  ├─ [공격2] MySQL 자격증명... ❌ (8초)
  ├─ [공격3] SQL Injection... ⏱️ (45초 - 타임아웃 설정됨)
  └─ ...
```

**규칙**:
- 포괄 승인 후 사용자 개입 없음
- 각 공격마다 타임아웃 설정 (기본 30초)
- Blacklist 공격이 발견되면 즉시 중단하고 "거절됨" 로깅
- stdout/stderr 완전 보존

---

### 단계 4: 증거 로깅 (Evidence) — 완전 자동

```
각 공격마다:
[Control ID] | [명령] | [시간] | [결과] | [증거 파일]
apache-001   | curl   | 3s    | ✓     | evidence/apache-001.txt
mysql-001    | mysql  | 8s    | ❌    | evidence/mysql-001.txt
sqli-001     | curl   | 45s   | ⏱️   | evidence/sqli-001.txt (TIMEOUT)
```

**분류**:
- **FACT**: stdout, stderr, exit code, 응답 바디 전문
- **INFERENCE**: "이 결과가 의미하는 바" → AI 작성, 명시 필수
- **UNKNOWN**: "판단 불가" → 삭제 금지, 그대로 보존

---

## 금지 행동 감지 (Safety Validator)

AI가 매 명령 실행 전에 **항상** 체크:

```python
def validate_command(cmd):
    if "hydra" in cmd or "john" in cmd or "hashcat" in cmd:
        return REJECT("브루트포스는 금지됨")
    
    if "-a" in cmd and "20" in cmd:  # nmap all ports
        return REJECT("모든 포트 스캔은 금지됨")
    
    if "DELETE" in cmd.upper() or "DROP" in cmd.upper():
        return REJECT("데이터 파괴는 금지됨")
    
    if "rm " in cmd and "/" in cmd:
        return REJECT("파일 삭제는 금지됨")
    
    if "slowloris" in cmd.lower() or "ab -c 1000" in cmd:
        return REJECT("DoS는 금지됨")
    
    return OK
```

거절 시 메시지:

```
❌ 명령이 안전 정책 위반:
   사유: {이유}
   명령: {cmd}
   
이 명령은 실행될 수 없습니다.
대신 시도해볼 수 있는 것:
  - {대안 1}
  - {대안 2}
```

---

## "사람에게 남는 결정"

AI는 **절대** 이것들을 결정하지 않습니다:

```
❌ AI는 Scope를 승인하지 않는다
   "이 IP 괜찮나요?" → 항상 사용자 확인

❌ AI는 성공을 확정하지 않는다
   "Flag를 찾았습니다" → AI draft일 뿐
   "이 게 맞는 Flag인가요?" → 사용자만 판단

❌ AI는 Evidence를 최종 확정하지 않는다
   기록은 자동 생성되지만, 어떤 걸 제출할지는 사용자 결정

✅ AI는 이것들만 함
   - Tool Observation 기록
   - FACT/INFERENCE 분류
   - 실행 로그 자동 생성
   - 다음 단계 제안
```

---

## Execution Log 형식

각 run마다 자동으로 생성되는 `execution.log`:

```
[2026-10-29 16:45:23] === CTF AUTO HARNESS START ===
[2026-10-29 16:45:23] Target: 192.168.1.100
[2026-10-29 16:45:23] Mode: CTF
[2026-10-29 16:45:23] User Approval: pending

[2026-10-29 16:45:24] [SCAN-001] nmap -sT -p- 192.168.1.100
[2026-10-29 16:45:45] [SCAN-001] ✓ COMPLETED (21 seconds)
[2026-10-29 16:45:45] [SCAN-001] OUTPUT:
  22/tcp open ssh OpenSSH 7.4
  80/tcp open http Apache 2.4.41
  3306/tcp open mysql MySQL 5.7.28

[2026-10-29 16:45:46] [ADVISOR] Analyzing...
[2026-10-29 16:45:47] [ADVISOR] Proposed 5 attacks
[2026-10-29 16:45:47] [PENDING] Waiting for user approval...

[2026-10-29 16:45:52] User Input: "go"
[2026-10-29 16:45:52] [APPROVAL] Blanket approval granted for proposed attacks

[2026-10-29 16:45:53] [ATTACK-001] Apache Header Analysis
[2026-10-29 16:45:53] Command: curl -i -s http://192.168.1.100
[2026-10-29 16:45:56] ✓ COMPLETED (3 seconds)
[2026-10-29 16:45:56] STDOUT:
  Server: Apache/2.4.41 (Ubuntu)
[2026-10-29 16:45:56] STDERR: (none)
[2026-10-29 16:45:56] EXIT CODE: 0

[2026-10-29 16:45:57] [ATTACK-002] MySQL Brute Force (top 10 creds)
[2026-10-29 16:45:57] Command: mysql -h 192.168.1.100 -u root -proot
[2026-10-29 16:46:05] ❌ COMPLETED (8 seconds) - ACCESS DENIED
[2026-10-29 16:46:05] STDERR: ERROR 1045 (28000): Access denied for user 'root'@'192.168.1.100'

[2026-10-29 16:46:06] [ATTACK-003] SQL Injection (basic payload)
[2026-10-29 16:46:06] Command: curl -s "http://192.168.1.100/search.php?q=1' OR '1'='1"
[2026-10-29 16:46:51] ⏱️ TIMEOUT (45 seconds - exceeds 45s limit)
[2026-10-29 16:46:51] STDOUT: (partial - first 500 chars)
[2026-10-29 16:46:51] RESULT: TIMEOUT

[2026-10-29 16:46:52] === ANALYSIS ===
[2026-10-29 16:46:52] FACT: Apache version 2.4.41 disclosed
[2026-10-29 16:46:52] INFERENCE: Possible CVE-2021-xxxxx in this version
[2026-10-29 16:46:52] FACT: MySQL root@localhost not accessible from remote
[2026-10-29 16:46:52] INFERENCE: MySQL configured with proper access control

[2026-10-29 16:46:53] === SESSION END ===
[2026-10-29 16:46:53] Total Time: 90 seconds
[2026-10-29 16:46:53] Attacks Executed: 3
[2026-10-29 16:46:53] Successful: 1
[2026-10-29 16:46:53] Failed: 1
[2026-10-29 16:46:53] Timeout: 1
```

---

## 예외 상황 처리

### 상황 1: 공격이 타임아웃되면?

```
[ATTACK-003] SQL Injection... ⏱️ TIMEOUT (45s)

→ [AI] 결과 저장, "타임아웃" 명시
→ [AI] 대안 제안:
    "응답이 매우 느립니다. 가능성:"
    "1. SQL injection이 작동 중 (Time-based detection)"
    "2. 서버가 과부하 상태"
    "3. 네트워크 지연"

→ [사용자] 판단해서 다음 action 결정
```

### 상황 2: Blacklist 공격이 제안되면?

예: 사용자가 `--attacks "brute_ssh"` 라고 명시한 경우

```
❌ 요청된 공격이 안전 정책 위반:
   공격: brute_ssh (SSH 브루트포스)
   사유: 서버 응답 시간 초과, 대회 규칙 위반
   
이 공격은 실행될 수 없습니다.

대신 시도해볼 수 있는 것:
  - SSH 버전 열거 (service detection)
  - 알려진 SSH CVE 테스트 (고정 payload만)
```

### 상황 3: 사용자가 "skip"을 선택하면?

```
[사용자] skip

→ [AI] 모든 공격 건너뛰기
→ 스캔 결과만 저장
→ 보고서 생성 (정찰 정보만)
```

---

## 자동 보고서 생성

각 run이 끝나면 `runs/{timestamp}/report.md` 자동 생성:

```markdown
# CTF Auto Harness Report

**타겟**: 192.168.1.100  
**모드**: CTF  
**시간**: 2026-10-29 16:45-16:47  
**총 소요**: 2분 34초  

## 정찰 결과 (Reconnaissance)

### FACT
- 열린 포트: 22 (SSH), 80 (HTTP), 3306 (MySQL)
- SSH: OpenSSH 7.4
- HTTP: Apache 2.4.41
- MySQL: 5.7.28

### INFERENCE
- OpenSSH 7.4는 CVE-2018-15473 취약 (정보 유출)
- Apache 2.4.41는 알려진 RCE 없음
- MySQL이 외부 접근 가능 (위험)

## 공격 시도 (Exploitation)

| # | 공격명 | 결과 | 시간 | 비고 |
|-|-|-|-|-|
| 1 | Apache 헤더 분석 | ✓ | 3s | 버전 확인 |
| 2 | MySQL 기본 자격증명 | ❌ | 8s | 접근 거부 |
| 3 | SQL Injection | ⏱️ | 45s | TIMEOUT |

## 다음 단계

### 성공 가능성 높음
1. OpenSSH 7.4 CVE-2018-15473 테스트
   - `ssh -vv root@192.168.1.100` 로 버전 버그 트리거
   
2. MySQL 웹 인터페이스 탐색
   - phpMyAdmin 또는 다른 관리 도구 존재 확인

### 주의 사항
- SQL Injection이 느리므로, Time-based 공격 시도 가능
- 하지만 서버 부하로 인한 DoS 위험 있음

---

**보고서 작성**: AI 초안  
**최종 판단**: 사용자 책임
```

---

## 요약: 3가지 핵심 규칙

| 규칙 | 내용 |
|------|------|
| **Blacklist** | 브루트포스, DDoS, 데이터 파괴는 절대 금지 |
| **Semi-Auto** | 정찰은 자동, 공격은 사용자 승인 후 자동 |
| **Evidence** | 모든 실행 결과 보존, FACT/INFERENCE 구분 |

이 계약을 벗어나는 요청은 AI가 거절합니다.

