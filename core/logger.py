"""
Evidence Logger — 모든 공격 결과를 기록
FACT / INFERENCE 구분하여 저장
"""

import os
import json
import time
from datetime import datetime
from pathlib import Path


class Logger:
    """공격 실행 결과 로깅"""

    def __init__(self, run_dir: str):
        """
        Args:
            run_dir: 이번 실행의 디렉토리 (예: runs/2026-10-29_16-45-23)
        """
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)

        self.evidence_dir = self.run_dir / "evidence"
        self.evidence_dir.mkdir(exist_ok=True)

        self.execution_log = self.run_dir / "execution.log"
        self.results_json = self.run_dir / "results.json"

        self.start_time = time.time()
        self.results = {
            "start_time": datetime.now().isoformat(),
            "target": None,
            "mode": None,
            "scans": [],
            "attacks": [],
            "analysis": {},
        }

    def set_target(self, target: str, mode: str):
        """타겟과 모드 설정"""
        self.results["target"] = target
        self.results["mode"] = mode
        self._log(f"=== CTF AUTO HARNESS START ===")
        self._log(f"Target: {target}")
        self._log(f"Mode: {mode}")

    def log_scan(self, scan_id: str, command: str, output: str, duration: float):
        """정찰 결과 기록"""
        record = {
            "scan_id": scan_id,
            "command": command,
            "timestamp": datetime.now().isoformat(),
            "duration": duration,
            "status": "completed",
        }

        # stdout를 파일로 저장
        evidence_file = self.evidence_dir / f"{scan_id}.txt"
        evidence_file.write_text(output, encoding="utf-8")
        record["evidence_file"] = str(evidence_file)

        self._log(f"[{scan_id}] {command}")
        self._log(f"[{scan_id}] ✓ COMPLETED ({duration:.1f}s)")
        self._log(f"[{scan_id}] OUTPUT: {len(output)} bytes")

        self.results["scans"].append(record)

    def log_attack(
        self,
        attack_id: str,
        attack_name: str,
        command: str,
        stdout: str,
        stderr: str,
        exit_code: int,
        duration: float,
        status: str = "completed",
    ):
        """
        공격 실행 결과 기록

        Args:
            attack_id: 공격 ID (예: apache-001)
            attack_name: 공격 이름
            command: 실행된 명령
            stdout: 표준 출력
            stderr: 표준 에러
            exit_code: 종료 코드
            duration: 소요 시간
            status: 상태 (completed, failed, timeout, rejected)
        """
        record = {
            "attack_id": attack_id,
            "name": attack_name,
            "command": command,
            "timestamp": datetime.now().isoformat(),
            "duration": duration,
            "exit_code": exit_code,
            "status": status,
        }

        # 결과를 파일로 저장
        evidence_file = self.evidence_dir / f"{attack_id}.txt"
        evidence_content = f"""=== {attack_name} ===
Command: {command}
Exit Code: {exit_code}
Duration: {duration:.1f}s
Status: {status}

--- STDOUT ---
{stdout}

--- STDERR ---
{stderr}
"""
        evidence_file.write_text(evidence_content, encoding="utf-8")
        record["evidence_file"] = str(evidence_file)

        # 로그에 기록
        status_emoji = {
            "completed": "✓",
            "failed": "❌",
            "timeout": "⏱️",
            "rejected": "⛔",
        }
        emoji = status_emoji.get(status, "?")

        self._log(f"[{attack_id}] {attack_name}")
        self._log(f"[{attack_id}] Command: {command}")
        self._log(f"[{attack_id}] {emoji} {status.upper()} ({duration:.1f}s, exit={exit_code})")

        if stdout:
            self._log(f"[{attack_id}] STDOUT ({len(stdout)} bytes):")
            for line in stdout.split("\n")[:5]:  # 첫 5줄만 로그
                if line:
                    self._log(f"  {line}")
            if len(stdout.split("\n")) > 5:
                self._log(f"  ... ({len(stdout.split(chr(10)))} lines total)")

        if stderr:
            self._log(f"[{attack_id}] STDERR: {stderr[:100]}")

        self.results["attacks"].append(record)

    def log_analysis(self, analysis_dict: dict):
        """분석 결과 기록 (FACT/INFERENCE/UNKNOWN)"""
        self.results["analysis"] = analysis_dict

        self._log("\n=== ANALYSIS ===")
        for key, value in analysis_dict.items():
            if isinstance(value, list):
                self._log(f"{key}:")
                for item in value:
                    self._log(f"  - {item}")
            else:
                self._log(f"{key}: {value}")

    def log_user_approval(self, approval_text: str):
        """사용자 승인 기록"""
        self._log(f"\n[APPROVAL] {approval_text}")

    def _log(self, message: str):
        """로그 파일에 기록"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_line = f"[{timestamp}] {message}\n"

        with open(self.execution_log, "a", encoding="utf-8") as f:
            f.write(log_line)

        print(message)

    def finalize(self):
        """세션 종료 및 최종 보고서 생성"""
        self.results["end_time"] = datetime.now().isoformat()
        self.results["total_duration"] = time.time() - self.start_time

        # JSON으로 저장
        with open(self.results_json, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        # 요약 로그
        self._log("\n=== SESSION END ===")
        self._log(f"Total Time: {self.results['total_duration']:.1f}s")
        self._log(f"Scans Executed: {len(self.results['scans'])}")
        self._log(f"Attacks Executed: {len(self.results['attacks'])}")

        successful = sum(1 for a in self.results["attacks"] if a["status"] == "completed")
        failed = sum(1 for a in self.results["attacks"] if a["status"] == "failed")
        timeout = sum(1 for a in self.results["attacks"] if a["status"] == "timeout")
        rejected = sum(1 for a in self.results["attacks"] if a["status"] == "rejected")

        self._log(f"Successful: {successful}")
        self._log(f"Failed: {failed}")
        self._log(f"Timeout: {timeout}")
        self._log(f"Rejected: {rejected}")

        # 보고서 생성
        self._generate_report()

        print(f"\n📄 Report saved: {self.run_dir}/report.md")
        print(f"📊 Results JSON: {self.run_dir}/results.json")
        print(f"📋 Execution log: {self.run_dir}/execution.log")

    def _generate_report(self):
        """자동 분석 보고서 생성"""
        report_path = self.run_dir / "report.md"

        with open(report_path, "w", encoding="utf-8") as f:
            f.write("# CTF Auto Harness Report\n\n")
            f.write(f"**타겟**: {self.results['target']}\n")
            f.write(f"**모드**: {self.results['mode']}\n")
            f.write(f"**시간**: {self.results['start_time']}\n")
            f.write(f"**총 소요**: {self.results['total_duration']:.1f}초\n\n")

            # 정찰 결과
            f.write("## 정찰 결과 (Reconnaissance)\n\n")
            if self.results["scans"]:
                for scan in self.results["scans"]:
                    f.write(f"### {scan['scan_id']}\n")
                    f.write(f"- 명령: `{scan['command']}`\n")
                    f.write(f"- 소요시간: {scan['duration']:.1f}s\n")
                    f.write(f"- 증거: {scan['evidence_file']}\n\n")

            # 공격 시도
            f.write("## 공격 시도 (Exploitation)\n\n")
            f.write("| # | 공격명 | 결과 | 시간 | 증거 |\n")
            f.write("|---|--------|------|------|------|\n")

            for i, attack in enumerate(self.results["attacks"], 1):
                status_emoji = {
                    "completed": "✓",
                    "failed": "❌",
                    "timeout": "⏱️",
                    "rejected": "⛔",
                }
                emoji = status_emoji.get(attack["status"], "?")
                f.write(
                    f"| {i} | {attack['name']} | {emoji} | {attack['duration']:.1f}s "
                    f"| {Path(attack['evidence_file']).name} |\n"
                )

            # 분석
            if self.results["analysis"]:
                f.write("\n## 분석 (FACT / INFERENCE)\n\n")
                for key, value in self.results["analysis"].items():
                    f.write(f"### {key}\n")
                    if isinstance(value, list):
                        for item in value:
                            f.write(f"- {item}\n")
                    else:
                        f.write(f"{value}\n")

            f.write("\n---\n\n")
            f.write("**참고**: 이 보고서는 AI 초안입니다. 최종 판단은 사용자의 책임입니다.\n")
