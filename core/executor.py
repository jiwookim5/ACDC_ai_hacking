"""
Executor — 실제 공격 실행 및 증거 기록
"""

import subprocess
import time
from typing import Dict, Tuple
from .validator import SafetyValidator
from .logger import Logger


class Executor:
    """공격 실행 엔진"""

    def __init__(self, target: str, logger: Logger):
        """
        Args:
            target: 공격 대상 IP/도메인
            logger: 증거 로거
        """
        self.target = target
        self.logger = logger
        self.validator = SafetyValidator()
        self.attack_counter = {}

    def execute_attacks(self, attacks: list, skip_validation: bool = False) -> Dict:
        """
        공격들을 순차적으로 실행

        Args:
            attacks: 실행할 공격 리스트
            skip_validation: 검증 건너뛰기 (테스트용)

        Returns:
            실행 결과 요약
        """
        results = {
            "total": len(attacks),
            "successful": 0,
            "failed": 0,
            "timeout": 0,
            "rejected": 0,
        }

        print("\n" + "=" * 75)
        print(f"공격 실행 중 ({len(attacks)}개)...")
        print("=" * 75 + "\n")

        for i, attack in enumerate(attacks, 1):
            attack_id = attack.get("id", f"attack_{i}")
            attack_name = attack.get("name", "Unknown")

            print(f"[{i}/{len(attacks)}] {attack_name}...", end=" ", flush=True)

            status, stdout, stderr, duration = self._execute_single_attack(
                attack, skip_validation
            )

            # 상태 표시
            status_symbols = {
                "completed": "✓",
                "failed": "❌",
                "timeout": "⏱️",
                "rejected": "⛔",
            }
            symbol = status_symbols.get(status, "?")
            print(f"{symbol} ({duration:.1f}s)")

            # 결과 기록
            self.logger.log_attack(
                attack_id=attack_id,
                attack_name=attack_name,
                command=attack.get("command", ""),
                stdout=stdout,
                stderr=stderr,
                exit_code=0 if status == "completed" else -1,
                duration=duration,
                status=status,
            )

            # 통계 업데이트
            results[status] += 1

        print("\n" + "=" * 75)
        print("공격 실행 완료")
        print(f"  ✓ 성공: {results['successful']}")
        print(f"  ❌ 실패: {results['failed']}")
        print(f"  ⏱️ 타임아웃: {results['timeout']}")
        print(f"  ⛔ 거절됨: {results['rejected']}")
        print("=" * 75 + "\n")

        return results

    def _execute_single_attack(
        self, attack: Dict, skip_validation: bool = False
    ) -> Tuple[str, str, str, float]:
        """
        하나의 공격 실행

        Args:
            attack: 공격 설정
            skip_validation: 검증 건너뛰기

        Returns:
            (status, stdout, stderr, duration)
            status: "completed", "failed", "timeout", "rejected"
        """
        attack_id = attack.get("id", "unknown")
        command = attack.get("command", "")
        timeout = attack.get("timeout", 30)

        # 플레이스홀더 치환
        command = command.replace("{target}", self.target)
        command = command.replace("{output}", f"/tmp/{attack_id}_output.txt")

        start_time = time.time()

        # 1. 안전성 검증
        if not skip_validation:
            is_safe, reason = self.validator.validate(command, attack_id)
            if not is_safe:
                duration = time.time() - start_time
                # 거절 메시지 출력 (한 번만)
                if attack_id not in self.attack_counter:
                    self.validator.print_rejection(command, attack_id)
                self.attack_counter[attack_id] = True
                return "rejected", "", reason, duration

        # 2. 명령 실행
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            duration = time.time() - start_time
            stdout = result.stdout[:5000]  # 5000자 제한
            stderr = result.stderr[:1000]  # 에러는 짧게

            # 성공 여부 판단
            status = "completed" if result.returncode == 0 else "failed"

            return status, stdout, stderr, duration

        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            return "timeout", "", f"타임아웃 ({timeout}s 초과)", duration
        except Exception as e:
            duration = time.time() - start_time
            return "failed", "", str(e), duration

    def generate_analysis(self, logger_results: Dict) -> Dict:
        """
        공격 결과 분석 및 FACT/INFERENCE 생성

        Returns:
            분석 결과 딕셔너리
        """
        analysis = {
            "FACT": [],
            "INFERENCE": [],
            "UNKNOWN": [],
        }

        for attack in logger_results["attacks"]:
            if attack["status"] == "completed":
                # FACT: 실행 결과
                analysis["FACT"].append(
                    f"{attack['name']}: {attack['evidence_file']}에서 확인"
                )

                # INFERENCE: 의미 해석
                if "header" in attack["name"].lower():
                    analysis["INFERENCE"].append(
                        "서버 버전 정보 누출 (기술 스택 파악 가능)"
                    )
                elif "brute" in attack["name"].lower():
                    analysis["INFERENCE"].append("자격증명 관리 강도 확인됨")
                elif "sql" in attack["name"].lower():
                    analysis["INFERENCE"].append(
                        "입력 검증 여부 확인 (필터링 우회 가능성)"
                    )

            elif attack["status"] == "timeout":
                analysis["UNKNOWN"].append(
                    f"{attack['name']}: 타임아웃 - 원인 불명확"
                )
            elif attack["status"] == "rejected":
                analysis["FACT"].append(
                    f"{attack['name']}: 안전 정책으로 거절됨"
                )

        return analysis
