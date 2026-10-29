"""
Scanner — 정찰 수행 (nmap, 서비스 식별)
"""

import subprocess
import re
from typing import Dict, List, Tuple


class Scanner:
    """네트워크 및 서비스 정찰"""

    def __init__(self, target: str):
        self.target = target
        self.services = {}
        self.open_ports = []

    def scan_ports(self) -> Tuple[bool, str]:
        """
        nmap으로 포트 스캔
        Returns: (success: bool, output: str)
        """
        try:
            print("[*] nmap 포트 스캔 중...")
            cmd = f"nmap -sT -p- --service-info {self.target} 2>/dev/null"
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=60
            )

            output = result.stdout
            self._parse_nmap_output(output)

            return True, output

        except subprocess.TimeoutExpired:
            return False, "nmap 타임아웃 (60s)"
        except Exception as e:
            return False, str(e)

    def _parse_nmap_output(self, output: str):
        """nmap 결과 파싱"""
        # 포트 정보 추출: 22/tcp open ssh OpenSSH 7.4
        pattern = r"(\d+)/tcp\s+open\s+(\S+)\s+(.*)"

        for match in re.finditer(pattern, output):
            port = int(match.group(1))
            service = match.group(2)
            version = match.group(3).strip()

            self.open_ports.append(port)
            self.services[port] = {
                "service": service,
                "version": version,
                "port": port,
            }

    def get_summary(self) -> Dict:
        """정찰 결과 요약"""
        return {
            "target": self.target,
            "open_ports": self.open_ports,
            "services": self.services,
            "total_services": len(self.services),
        }

    def print_summary(self):
        """결과 출력"""
        print(f"\n[+] 정찰 완료:")
        print(f"    타겟: {self.target}")
        print(f"    열린 포트: {len(self.open_ports)}개")

        if self.services:
            print("\n    [서비스 목록]")
            for port, info in sorted(self.services.items()):
                print(
                    f"    {port:5d}/tcp {info['service']:10s} {info['version']}"
                )
        else:
            print("    (서비스 감지 안 됨)")
