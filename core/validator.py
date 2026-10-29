"""
Safety Validator — 모든 명령의 안전성 검증
CONTRACT.md의 Blacklist를 강제함
"""

import re
from typing import Tuple

BLACKLIST = {
    "brute_force": [
        r"hydra",
        r"john\s",
        r"hashcat",
        r"medusa",
        r"password.*brute",
        r"crack",
    ],
    "dos": [
        r"slowloris",
        r"ab\s+-c\s+[0-9]{3,}",
        r"wrk\s+-c\s+[0-9]{3,}",
        r"hping",
        r"flood",
        r"ddos",
    ],
    "directory_scan": [
        r"gobuster",
        r"wfuzz\s+-w",
        r"dirb\s+",
        r"dirbuster",
    ],
    "data_destruction": [
        r"^\s*(DELETE|DROP|TRUNCATE)",
        r"rm\s+/",
        r"dd\s+if=",
        r"shred\s+",
    ],
    "privilege_escalation": [
        r"reverse\s+shell",
        r"bash\s+-i",
        r"mkfifo",
        r"nc\s+-e",
        r"/dev/tcp",
    ],
}


class SafetyValidator:
    """명령 안전성 검증"""

    def __init__(self, blacklist_dict=None):
        self.blacklist = blacklist_dict or BLACKLIST
        self.violations = []

    def validate(self, command: str, attack_id: str = "") -> Tuple[bool, str]:
        """
        명령이 안전한지 검증

        Args:
            command: 실행할 쉘 명령
            attack_id: 공격 ID (로깅용)

        Returns:
            (is_safe: bool, reason: str)
            - True, "" → 안전함
            - False, "reason" → 거절됨
        """
        command_lower = command.lower()

        for category, patterns in self.blacklist.items():
            for pattern in patterns:
                if re.search(pattern, command_lower, re.IGNORECASE):
                    reason = f"[{category.upper()}] {pattern} 발견됨"
                    self.violations.append({
                        "attack_id": attack_id,
                        "command": command,
                        "category": category,
                        "pattern": pattern,
                    })
                    return False, reason

        return True, ""

    def reject_reason(self, category: str) -> str:
        """거절 이유 제시"""
        reasons = {
            "brute_force": "브루트포스는 서버 응답 시간 초과와 DoS를 유발할 수 있어 금지됩니다.",
            "dos": "DoS/DDoS 공격은 대회 규칙 위반입니다.",
            "directory_scan": "무제한 스캔은 브루트포스로 귀결되어 금지됩니다.",
            "data_destruction": "데이터 파괴는 대회 규칙 및 법률 위반입니다.",
            "privilege_escalation": "백도어/지속성 확보는 금지됩니다.",
        }
        return reasons.get(category, "안전 정책 위반")

    def suggest_alternative(self, attack_id: str, original_command: str) -> list:
        """거절된 공격에 대한 대안 제시"""
        suggestions = {
            "brute_force": [
                "SSH 버전 열거 (배너만, 자격증명 테스트 X)",
                "기본 자격증명 테스트 (top 10만, 무제한 X)",
                "알려진 취약점 기반 단일 payload 테스트",
            ],
            "dos": [
                "포트 스캔 (nmap -sT, 느린 속도)",
                "서비스 버전 열거 (연결 1회)",
                "리소스 모니터링 (curl로 응답 시간만 측정)",
            ],
            "directory_scan": [
                "수동 경로 추측 (특정 경로만, 예: /admin, /backup)",
                "주요 파일명만 테스트 (robots.txt, .git, .env)",
            ],
            "data_destruction": [
                "읽기 전용 명령으로 정보 수집",
                "스크린샷/스크린 기록으로 증거 남기기",
            ],
            "privilege_escalation": [
                "권한 확인 (id, whoami)",
                "이용 가능한 명령 확인 (sudo -l)",
            ],
        }

        # 위반 내용 분석
        for category in self.blacklist.keys():
            for pattern in self.blacklist[category]:
                if re.search(pattern, original_command.lower()):
                    return suggestions.get(category, [])

        return []

    def print_rejection(self, command: str, attack_id: str = ""):
        """거절 메시지 출력"""
        is_safe, reason = self.validate(command, attack_id)

        if not is_safe:
            print("\n" + "=" * 70)
            print("❌ 명령이 안전 정책 위반")
            print("=" * 70)
            if attack_id:
                print(f"공격 ID: {attack_id}")
            print(f"명령: {command}")
            print(f"사유: {reason}")
            print()

            # 카테고리 추출
            category = reason.split("]")[0].replace("[", "").lower()
            reason_text = self.reject_reason(category)
            print(f"설명: {reason_text}")
            print()

            # 대안 제시
            alternatives = self.suggest_alternative(attack_id, command)
            if alternatives:
                print("대신 시도해볼 수 있는 것:")
                for i, alt in enumerate(alternatives, 1):
                    print(f"  {i}. {alt}")
            print("=" * 70 + "\n")
