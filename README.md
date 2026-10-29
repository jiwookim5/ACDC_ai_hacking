# Auto CTF Harness — 반자동 CTF 공격/방어 하네스

IP 주소만 입력하면 자동으로 정찰, 공격 제안, 증거 기록을 수행하는 CTF 해킹 하네스입니다.

## 특징

- **반자동화 (Semi-Automation)**: 공격 제안 후 사용자 승인 필수
- **CTF 원칙 준수**: 서버 장애 유발 공격(브루트포스, DDoS) 금지
- **증거 완전 관리**: FACT/INFERENCE 구분, stdout/stderr 보존
- **시간 추적**: 각 공격마다 소요 시간 기록
- **빠른 회고**: 각 run마다 자동 분석 결과 생성

## 시작하기

### 사전 설치

```bash
# 필요한 도구 설치
brew install nmap hydra nikto jq

# Python 의존성
pip install pyyaml requests paramiko
```

### 기본 사용법

```bash
# 1. CTF 모드 (문제풀이)
./harness.sh 192.168.1.100 --mode ctf

# 2. KotH 모드 (방어)
./harness.sh 192.168.1.100 --mode koth

# 3. 특정 공격만 수행
./harness.sh 192.168.1.100 --attacks "web_scan,service_enum"
```

## 디렉토리 구조

```
auto-ctf-harness/
├── README.md                    (이 파일)
├── CONTRACT.md                  (AI 계약서 & 원칙)
├── harness.sh                   (메인 CLI 진입점)
│
├── core/
│   ├── __init__.py
│   ├── scanner.py               (nmap, 서비스 식별)
│   ├── advisor.py               (공격 제안 AI)
│   ├── executor.py              (공격 실행 엔진)
│   ├── logger.py                (증거 로깅)
│   └── validator.py             (안전성 검증)
│
├── config/
│   ├── attacks.yaml             (모든 공격 규칙)
│   ├── defenses.yaml            (방어 규칙)
│   └── blacklist.yaml           (절대 금지 공격)
│
├── payloads/                    (exploit/payload 모음)
│   ├── web/
│   ├── ssh/
│   ├── database/
│   └── template.py              (새 payload 템플릿)
│
├── runs/                        (각 실행마다 자동 생성)
│   └── {timestamp}/
│       ├── scan.json            (정찰 결과)
│       ├── proposed.json        (제안된 공격)
│       ├── approval.log         (사용자 승인)
│       ├── execution.log        (실행 결과)
│       ├── evidence/            (stdout/stderr)
│       └── report.md            (자동 분석)
│
└── .claude/
    └── CLAUDE.md                (프로젝트 지시사항)
```

## 핵심 원칙

### ✅ 허용되는 공격

- 웹 취약점 스캔 (Nikto, OWASP ZAP)
- 서비스 버전 열거
- SQL injection 테스트
- XSS 취약점 테스트
- 알려진 CVE exploit (제한된 시도)
- SSH 키 스캔

### ❌ 금지되는 공격

- **브루트포스** (비밀번호 추측 - 시간 오래 걸림)
- **DDoS/DoS** (서버 장애)
- **무제한 자동 스캔** (Nuclei full, Burp Pro auto attack)
- **데이터 파괴/삭제**
- **백도어/지속성** (웹셸, cron job, reverse shell)
- **Credential 수집 후 이용** (실제 데이터 조작)

## 예시: 첫 실행

```bash
$ ./harness.sh 192.168.1.100 --mode ctf

[1/5] 정찰 중...
      ✓ nmap 스캔 완료
      ✓ 서비스 식별: Apache 2.4.41, OpenSSH 7.4, MySQL 5.7.28

[2/5] 공격 제안 분석...

╔═══════════════════════════════════════════════════════════════╗
║ 추천 공격 순서 (위험도 낮은 것부터)                            ║
╠═══════════════════════════════════════════════════════════════╣
║ [1] Apache/2.4.41 헤더 분석              🟢 LOW    100% ║
║ [2] MySQL 기본 자격증명 테스트           🟡 MED     45% ║
║ [3] SSH 버전 열거                       🟢 LOW     95% ║
║ [4] HTTP OPTIONS 메서드 테스트           🟢 LOW     80% ║
║ [5] SQL Injection (기본 payload)        🟠 HIGH    30% ║
╚═══════════════════════════════════════════════════════════════╝

위 공격들을 실행할까요?
  [1] go         모두 순서대로
  [2] select     선택해서 (번호로: 1,3,5)
  [3] skip       건너뛰기
  [4] custom     커스텀 공격 추가

>>> go

[3/5] 공격 실행 중...
  [1/5] Apache 헤더 분석... ✓ (3초)
        발견: Server: Apache/2.4.41 (Ubuntu)
  [2/5] MySQL 기본 자격증명... ❌ (8초)
        결과: 접근 거부 (정상)
  [3/5] SSH 버전 열거... ✓ (2초)
        발견: OpenSSH 7.4 (CVE-2018-15473 가능)
  [4/5] OPTIONS 메서드... ✓ (1초)
        발견: Allow: GET, POST, PUT, DELETE (PUT은 위험)
  [5/5] SQL Injection... ❌ (45초)
        결과: 취약하지 않음 (쿼리 고정)

[4/5] 결과 분석...
  ⚠️ 주목할 점:
     - OpenSSH 7.4 취약점 발견 (정보 유출 가능)
     - PUT 메서드 활성화됨 (파일 업로드 가능성)

[5/5] 보고서 저장...
  📄 runs/2026-10-29_16-45-23/report.md

세션 종료: 총 59초 소요
```

## 다음 단계

1. `CONTRACT.md` 읽고 원칙 숙지
2. `config/attacks.yaml` 확인해서 어떤 공격들이 있는지 파악
3. `./harness.sh <IP> --list-attacks` 로 지원 공격 목록 조회
4. 첫 실행 시작!

## 문제 해결

### "permission denied" 에러

```bash
chmod +x harness.sh
```

### nmap/nikto 설치 안 됨

```bash
# macOS
brew install nmap nikto

# Ubuntu/Debian
sudo apt-get install nmap nikto
```

### Python 모듈 없음

```bash
pip install -r requirements.txt
```

---

**상태**: 초기 구현 완료, 테스트 대기 중
