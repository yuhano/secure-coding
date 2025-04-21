import re
import uuid
from decimal import Decimal, InvalidOperation
from markupsafe import escape

"""Input‑validation helpers for the Flask Market app."""

__all__ = [
    "validate_username",
    "validate_password",
    "validate_uuid4",
    "clean_text",
    "validate_price",
]

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
PW_POLICY_RE = re.compile(
    r"""(?=^.{8,64}$)      # 전체 길이
        (?=.*[A-Z])        # 대문자
        (?=.*[a-z])        # 소문자
        (?=.*\d)           # 숫자
        (?=.*[~!@#$%^&*])  # 특수문자
    """,
    re.X,
)

def _strip(value: str) -> str:
    """모든 입력은 strip 후 반환(앞뒤 공백 허용 안함)."""
    return (value or "").strip()

def _require(value: str, field: str) -> str:
    if not _strip(value):
        raise ValueError(f"{field}을(를) 입력하세요.")
    return value.strip()

def clean_text(text: str, *, max_len=500, blank_ok=False) -> str:
    text = _strip(text)
    if not text and not blank_ok:
        raise ValueError("내용을 입력하세요.")
    if len(text) > max_len:
        raise ValueError("입력 길이가 너무 깁니다.")
    return escape(text)

def validate_username(username: str) -> str:
    """Ensure username contains 3‑20 alphanumerics/underscores."""
    username = _require(username, "사용자명")
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("사용자명은 3~20자의 영문/숫자/밑줄만 가능합니다.")
    return username


def validate_password(password: str) -> str:
    """Require minimum password length of 8."""
    password = _require(password, "비밀번호")
    if not PW_POLICY_RE.search(password):
        raise ValueError(
            "비밀번호는 8~64자, 대/소문자·숫자·특수문자를 모두 포함해야 합니다."
        )
    return password


def validate_uuid4(value: str) -> bool:
    """Return True if *value* is a valid UUID4 string."""
    value = _require(value, "UUID")
    try:
        uuid.UUID(value, version=4)
        return True
    except ValueError:
        return False


def validate_price(price_str: str) -> Decimal:
    """Return price as a string with max two decimals, > 0."""
    price_str  = _require(price_str, "가격")
    try:
        price = Decimal(price_str)
        if price <= 0:
            raise ValueError
    except (InvalidOperation, ValueError):
        raise ValueError("가격은 0보다 큰 숫자여야 합니다.")
    return price.quantize(Decimal("0.01"))
