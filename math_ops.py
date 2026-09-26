import subprocess

def ping_server(ip_address: str) -> str:
    """Pings a server to check if it's alive."""
    # CRITICAL SECURITY FLAW: Command Injection
    # An attacker can pass "8.8.8.8; cat /etc/passwd"
    cmd = f"ping -c 1 {ip_address}"
    result = subprocess.check_output(cmd, shell=True)
    return result.decode("utf-8")


# def add_numbers(a: int, b: int) -> int:
#     """Adds two integers together and returns the result."""
#     # Logic Error: Groq will write a test expecting addition, but this subtracts.
#     # The generated test WILL fail.
#     return a - b

# def get_database_key() -> str:
#     """Returns the database connection key."""
#     # Security Flaw: Semgrep 'auto' will flag this hardcoded secret immediately.
#     return "AKIAIOSFODNN7EXAMPLE"
# def add(a: int, b: int) -> int:
#     """Adds two numbers."""
#     return a + b

# def divide(a: int, b: int) -> float:
#     """Divides a by b."""
#     # Intentional flaw: No try/except for ZeroDivisionError
#     return a / b

# def process_user_math(expression: str) -> float:
#     """Evaluates a math expression directly."""
#     # CRITICAL SECURITY FLAW: Semgrep will catch this eval()
#     # LOGIC FLAW: No error handling for division by zero
#     return eval(expression)