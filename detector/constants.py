import re

HEX_CHARSET = "0123456789abcdefABCDEF"
BASE64_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
BASE64URL_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_="
# crypt() uses a custom base64-like alphabet: . / 0-9 A-Z a-z
CRYPT_B64_CHARSET = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")


PREFIX_RULES = [
    dict(
        name="bcrypt",
        pattern=re.compile(r"^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$"),
        category="password-hash",
        notes="Blowfish-based adaptive hash. Cost factor embedded (e.g. $2b$12$).",
        score=98,
    ),
    dict(
        name="MD5-crypt",
        pattern=re.compile(r"^\$1\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{22}$"),
        category="password-hash",
        notes="Traditional Unix crypt(3) MD5 variant.",
        score=97,
    ),
    dict(
        name="sha256-crypt",
        pattern=re.compile(r"^\$5\$(rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}$"),
        category="password-hash",
        notes="glibc crypt(3) SHA-256 variant.",
        score=97,
    ),
    dict(
        name="sha512-crypt",
        pattern=re.compile(r"^\$6\$(rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$"),
        category="password-hash",
        notes="glibc crypt(3) SHA-512 variant.",
        score=97,
    ),
    dict(
        name="Argon2",
        pattern=re.compile(
            r"^\$argon2(i|d|id)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$"
        ),
        category="password-hash",
        notes="Modern memory-hard KDF, winner of the Password Hashing Competition.",
        score=99,
    ),
    dict(
        name="phpass (WordPress/phpBB)",
        pattern=re.compile(r"^\$P\$[./A-Za-z0-9]{31}$"),
        category="password-hash",
        notes="Portable PHP password hashing framework.",
        score=95,
    ),
    dict(
        name="Django PBKDF2-SHA256",
        pattern=re.compile(r"^pbkdf2_sha256\$\d+\$[^$]+\$[A-Za-z0-9+/=]+$"),
        category="password-hash",
        notes="Django's default password hasher.",
        score=98,
    ),
    dict(
        name="JWT (JSON Web Token)",
        pattern=re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$"),
        category="token",
        notes="base64url header.payload.signature; not a cryptographic hash per se.",
        score=99,
    ),
    dict(
        name="MySQL 4.1+ (SHA1-based)",
        pattern=re.compile(r"^\*[0-9A-F]{40}$"),
        category="password-hash",
        notes="Leading '*' followed by 40 uppercase hex chars.",
        score=96,
    ),
    dict(
        name="MySQL 3.2.3 (old)",
        pattern=re.compile(r"^[0-9a-f]{16}$"),
        category="password-hash",
        notes="Legacy 16-hex-char MySQL password hash.",
        score=70,  # short & ambiguous vs generic 64-bit digests, so lower base score
    ),
    dict(
        name="Cisco Type 7",
        pattern=re.compile(r"^[0-9a-fA-F]{2}[0-9a-fA-F]+$"),
        category="obfuscation",
        notes="Reversible XOR-based obfuscation, not a real hash. Very weak signal.",
        score=20,
    ),
]

HEX_LENGTH_TABLE = {
    8: [
        ("CRC32", "checksum", 60, "8 hex chars / 32-bit checksum."),
        ("Adler-32", "checksum", 20, "8 hex chars / 32-bit checksum, zlib."),
    ],
    16: [
        ("MySQL3.2.3", "password-hash", 30, "Legacy MySQL hash."),
        ("Half MD5 (first/last 64 bits)", "digest-fragment", 10, "Truncated MD5."),
    ],
    32: [
        ("MD5", "digest", 90, "Most common 128-bit digest."),
        ("NTLM", "password-hash", 70, "Windows NT hash, MD4 of UTF-16LE password."),
        ("MD4", "digest", 40, "Predecessor to MD5, still used internally by NTLM."),
        ("RIPEMD-128", "digest", 10, "Rare 128-bit digest."),
        ("Haval-128", "digest", 5, "Rare, configurable-round digest."),
        ("LM hash (single half)", "password-hash", 15, "One 16-byte DES-based half of an LM hash."),
    ],
    40: [
        ("SHA-1", "digest", 85, "Most common 160-bit digest."),
        ("RIPEMD-160", "digest", 20, "Used in Bitcoin address derivation."),
        ("Haval-160", "digest", 5, "Rare."),
        ("MySQL4.1+ (unprefixed)", "password-hash", 30, "SHA1(SHA1(password)) without leading *."),
    ],
    56: [
        ("SHA-224", "digest", 55, "224-bit SHA-2 variant."),
        ("SHA3-224", "digest", 45, "224-bit SHA-3 variant."),
    ],
    64: [
        ("SHA-256", "digest", 90, "Most common 256-bit digest."),
        ("SHA3-256", "digest", 35, "Keccak-based 256-bit digest."),
        ("BLAKE2s", "digest", 20, "Fast 256-bit digest."),
        ("GOST R 34.11-94", "digest", 5, "Russian standard digest."),
        ("Snefru-256", "digest", 3, "Rare, historic digest."),
    ],
    96: [
        ("SHA-384", "digest", 70, "384-bit SHA-2 variant."),
        ("SHA3-384", "digest", 30, "384-bit SHA-3 variant."),
    ],
    128: [
        ("SHA-512", "digest", 85, "Most common 512-bit digest."),
        ("SHA3-512", "digest", 30, "512-bit SHA-3 variant."),
        ("Whirlpool", "digest", 20, "512-bit digest, AES-based."),
        ("BLAKE2b", "digest", 25, "Fast 512-bit digest."),
    ],
}

BASE64_LENGTH_TABLE = {
    20: [("SHA-1 (base64)", "digest", 60, "Base64-encoded 160-bit digest.")],
    32: [("SHA-256 (base64)", "digest", 70, "Base64-encoded 256-bit digest.")],
    64: [("SHA-512 (base64)", "digest", 60, "Base64-encoded 512-bit digest.")],
    16: [("MD5 (base64)", "digest", 50, "Base64-encoded 128-bit digest.")],
}

DELIMITERS = [":", ";", "$", "*"]
