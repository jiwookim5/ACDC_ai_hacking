"""
Advisor — 발견된 서비스에 기반해 공격 제안
"""

import yaml
from pathlib import Path
from typing import List, Dict


class Advisor:
    """발견된 서비스에 맞는 공격 제안"""

    def __init__(self, config_file: str = "config/attacks.yaml"):
        """
        Args:
            config_file: attacks.yaml 경로
        """
        self.config_file = Path(config_file)
        self.attacks = self._load_attacks()

    def _load_attacks(self) -> Dict:
        """attacks.yaml 로드"""
        try:
            with open(self.config_file, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)
            return config.get("attacks", {})
        except Exception as e:
            print(f"[!] attacks.yaml 로드 실패: {e}")
            return {}

    def suggest(
        self, services: Dict, mode: str = "ctf"
    ) -> List[Dict]:
        """
        발견된 서비스에 기반해 공격 제안

        Args:
            services: 정찰 결과 서비스 정보
            mode: "ctf" 또는 "koth"

        Returns:
            제안된 공격 리스트 (위험도 낮은 순)
        """
        suggested = []

        # 기본 재감 공격들 (항상 추가)
        recon_attacks = self.attacks.get("reconnaissance", [])
        for attack in recon_attacks:
            suggested.append(attack)

        # 서비스별 공격 추천
        for port, service_info in services.items():
            service_name = service_info.get("service", "").lower()
            version = service_info.get("version", "").lower()

            # SSH 관련
            if service_name == "ssh":
                for attack in self.attacks.get("exploitation", []):
                    if "ssh" in attack.get("id", "").lower():
                        suggested.append(attack)

            # HTTP 관련
            elif service_name == "http" or service_name == "https":
                for attack in self.attacks.get("vulnerability", []):
                    if any(
                        x in attack.get("id", "").lower()
                        for x in ["web", "xss", "sqlmap"]
                    ):
                        suggested.append(attack)

            # MySQL 관련
            elif service_name == "mysql":
                for attack in self.attacks.get("vulnerability", []):
                    if "mysql" in attack.get("id", "").lower():
                        suggested.append(attack)

            # Tomcat 관련
            elif service_name == "tomcat":
                for attack in self.attacks.get("exploitation", []):
                    if "tomcat" in attack.get("id", "").lower():
                        suggested.append(attack)

        # 중복 제거 (attack_id 기반)
        seen = set()
        unique = []
        for attack in suggested:
            attack_id = attack.get("id")
            if attack_id and attack_id not in seen:
                seen.add(attack_id)
                unique.append(attack)

        # 위험도별 정렬
        risk_order = {"low": 0, "medium": 1, "high": 2}
        unique.sort(
            key=lambda x: risk_order.get(x.get("risk", "medium"), 1)
        )

        return unique

    def print_suggestions(self, attacks: List[Dict]):
        """제안 출력"""
        if not attacks:
            print("[*] 제안된 공격이 없습니다")
            return

        print("\n" + "=" * 75)
        print("추천 공격 순서 (위험도 낮은 것부터)")
        print("=" * 75)

        risk_emoji = {"low": "🟢", "medium": "🟡", "high": "🔴"}

        for i, attack in enumerate(attacks, 1):
            risk = attack.get("risk", "medium")
            emoji = risk_emoji.get(risk, "❓")
            name = attack.get("name", "Unknown")
            success_rate = attack.get("success_rate", 0)
            description = attack.get("description", "")

            print(
                f"{i:2d}. [{emoji}] {name:30s} ({success_rate}%) "
            )
            print(f"    → {description}")

        print("=" * 75)
        print()
        print("위 공격들을 실행할까요?")
        print("  [1] go         - 모두 순서대로 실행")
        print("  [2] select     - 선택해서 실행 (번호: 1,3,5 형식)")
        print("  [3] skip       - 건너뛰기")
        print("  [4] custom     - 커스텀 공격 추가")
        print()

    @staticmethod
    def parse_user_input(user_input: str, attacks: List[Dict]) -> List[Dict]:
        """
        사용자 입력 파싱

        Returns:
            선택된 공격 리스트, 또는 None
        """
        user_input = user_input.strip().lower()

        if user_input == "go":
            return attacks
        elif user_input == "skip":
            return []
        elif user_input == "select":
            # 사용자가 번호를 입력할 때까지 반복
            while True:
                try:
                    indices_input = input(
                        "공격 번호를 선택하세요 (쉼표로 구분, 예: 1,3,5): "
                    )
                    indices = [int(x.strip()) - 1 for x in indices_input.split(",")]
                    selected = [attacks[i] for i in indices if 0 <= i < len(attacks)]
                    return selected if selected else attacks
                except (ValueError, IndexError):
                    print("[!] 유효한 번호를 입력하세요")
        elif user_input == "custom":
            print("[*] 커스텀 공격 기능은 아직 미구현")
            return None
        else:
            print("[!] 유효한 입력이 아닙니다 (go/select/skip/custom)")
            return None
