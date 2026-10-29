#!/bin/bash

# CTF Auto Harness — 메인 진입점

set -e

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 사용법
usage() {
    cat << EOF
${BLUE}CTF Auto Harness${NC}
IP 주소를 입력하면 자동으로 정찰, 공격 제안, 실행을 수행합니다.

사용법:
  ./harness.sh <target_ip> [옵션]

옵션:
  --mode ctf|koth           모드 선택 (기본값: ctf)
  --attacks <id1,id2,...>   특정 공격만 실행
  --list-attacks            지원 공격 목록 출력
  --validate-only           검증만 수행 (실행 X)
  --skip-scan               정찰 건너뛰기

예시:
  ./harness.sh 192.168.1.100
  ./harness.sh 192.168.1.100 --mode koth
  ./harness.sh 192.168.1.100 --attacks apache_header,ssh_banner

EOF
    exit 1
}

# 검사: 필수 도구
check_dependencies() {
    local missing=()

    for cmd in python3 nmap curl; do
        if ! command -v "$cmd" &> /dev/null; then
            missing+=("$cmd")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}❌ 필수 도구 없음: ${missing[*]}${NC}"
        echo "설치 방법:"
        echo "  macOS: brew install ${missing[*]}"
        echo "  Ubuntu: sudo apt-get install ${missing[*]}"
        exit 1
    fi
}

# Python 스크립트 실행
run_harness() {
    local target=$1
    local mode=${2:-ctf}
    local attacks=$3

    local script_dir=$(cd "$(dirname "$0")" && pwd)
    cd "$script_dir"

    python3 << 'PYTHON_EOF'
import sys
import os
import time
from datetime import datetime
from pathlib import Path

# 경로 추가
sys.path.insert(0, os.getcwd())

from core import Scanner, Advisor, Executor, Logger, SafetyValidator

def main():
    target = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else "ctf"
    attacks_filter = sys.argv[3] if len(sys.argv) > 3 else None

    # 타임스탬프 기반 run 디렉토리 생성
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    run_dir = f"runs/{timestamp}"
    Path(run_dir).mkdir(parents=True, exist_ok=True)

    # 로거 초기화
    logger = Logger(run_dir)
    logger.set_target(target, mode)

    # 1. 정찰 (자동)
    print("\n" + "="*75)
    print("[1/4] 정찰 중...")
    print("="*75)

    scanner = Scanner(target)
    scan_success, scan_output = scanner.scan_ports()

    if scan_success:
        logger.log_scan("nmap_scan", f"nmap -sT -p- {target}", scan_output, 0)
        scanner.print_summary()
    else:
        print(f"❌ 정찰 실패: {scan_output}")
        logger.finalize()
        sys.exit(1)

    # 2. 공격 제안
    print("\n" + "="*75)
    print("[2/4] 공격 제안 분석...")
    print("="*75)

    advisor = Advisor("config/attacks.yaml")
    suggested_attacks = advisor.suggest(scanner.services, mode)
    advisor.print_suggestions(suggested_attacks)

    # 3. 사용자 승인 대기
    print("\n" + "="*75)
    print("[3/4] 사용자 승인 대기...")
    print("="*75)

    user_input = input(">>> ").strip().lower()

    selected_attacks = Advisor.parse_user_input(user_input, suggested_attacks)
    if selected_attacks is None:
        print("❌ 유효한 선택이 아닙니다")
        logger.finalize()
        sys.exit(1)

    if not selected_attacks:
        print("건너뛰기 선택됨")
        logger.finalize()
        sys.exit(0)

    logger.log_user_approval(f"포괄 승인: {len(selected_attacks)}개 공격")

    # 4. 공격 실행
    print("\n" + "="*75)
    print("[4/4] 공격 실행...")
    print("="*75)

    executor = Executor(target, logger)
    results = executor.execute_attacks(selected_attacks)

    # 분석 및 보고서
    analysis = executor.generate_analysis(logger.results)
    logger.log_analysis(analysis)

    logger.finalize()

    print(f"\n✅ 세션 완료!")
    print(f"📂 결과 디렉토리: {run_dir}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("❌ 타겟 IP를 입력하세요")
        print("사용법: ./harness.sh <target_ip> [옵션]")
        sys.exit(1)

    main()

PYTHON_EOF
}

# 메인 실행
main() {
    if [ $# -lt 1 ]; then
        usage
    fi

    target=$1
    shift

    # 옵션 파싱
    mode="ctf"
    attacks=""
    list_only=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --mode)
                mode="$2"
                shift 2
                ;;
            --attacks)
                attacks="$2"
                shift 2
                ;;
            --list-attacks)
                list_only=true
                shift
                ;;
            *)
                echo "❌ 알 수 없는 옵션: $1"
                usage
                ;;
        esac
    done

    echo -e "${BLUE}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════════════════════╗
║                         CTF AUTO HARNESS v1.0                                ║
║           IP 주소 하나로 자동 정찰, 공격 제안, 실행까지!                        ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"

    # 의존성 검사
    check_dependencies

    # 타겟 IP 검증
    if ! [[ $target =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] && \
       ! [[ $target =~ ^[a-zA-Z0-9.-]+$ ]]; then
        echo -e "${RED}❌ 유효한 IP 주소 또는 도메인이 아닙니다: $target${NC}"
        exit 1
    fi

    echo -e "${GREEN}타겟: $target${NC}"
    echo -e "${GREEN}모드: $mode${NC}"
    echo ""

    # 실행
    run_harness "$target" "$mode" "$attacks"
}

main "$@"
