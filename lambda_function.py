import json
import jwt
import urllib.request
from jwt.algorithms import RSAAlgorithm
import uuid
from datetime import datetime, timezone

COGNITO_USER_POOL_ID = "us-east-1_I0pEodCZM"
AWS_REGION = "us-east-1"

# JWKS URL for Cognito Public Keys
JWKS_URL = f"https://cognito-idp.{AWS_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}/.well-known/jwks.json"

# Cognito Issuer URL
ISSUER_URL = f"https://cognito-idp.{AWS_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}"

# Fetch Cognito public keys dynamically
def get_cognito_public_keys():
    with urllib.request.urlopen(JWKS_URL) as response:
        return json.loads(response.read().decode())["keys"]

PUBLIC_KEYS = get_cognito_public_keys()

def verify_token(token):
    try:
        # Extract JWT headers
        headers = jwt.get_unverified_header(token)
        kid = headers.get("kid")
        print(f"Token Headers: {headers}")
        print(f"Token kid: {repr(kid)}")
        print(f"Fetching JWKS from: {JWKS_URL}")
        print(f"Public Keys: {json.dumps(PUBLIC_KEYS, indent=2)}")

        # Match the correct public key
        token_kid = kid.strip() if kid else ""
        selected_key = next((key for key in PUBLIC_KEYS if key["kid"].strip() == token_kid), None)

        if not selected_key:
            raise Exception("Public key not found")

        print("✅ Match found! Proceeding with decoding...")
        print(f"Selected Key: {selected_key}")
        pem_key = RSAAlgorithm.from_jwk(json.dumps(selected_key))
        print(f"Converted PEM Key:\n{pem_key}")

        # Decode and verify the token with RS256 Algorithm
        decoded_token = jwt.decode(
            token,
            key=pem_key,
            algorithms=["RS256"],
            issuer=ISSUER_URL
        )

        print(f"Decoded Token: {decoded_token}")
        return decoded_token
    except jwt.ExpiredSignatureError:
        print("❌ Token expired!")
        raise Exception("Token expired")
    except jwt.InvalidTokenError as e:
        print(f"❌ Invalid token error: {str(e)}")
        raise Exception("Invalid token")
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")
        raise Exception(str(e))

def handler(event, context):
    try:
        print(f"Incoming Event: {json.dumps(event)}")

        # Extract and log the JWT token
        token = event["authorizationToken"].split(" ")[1]
        print(f"Extracted Token: {token[:20]}... (truncated for security)")

        # Verify and decode the token
        decoded_token = verify_token(token)

        # Allow access if the token is valid
        return {
            "principalId": decoded_token["sub"],
            "policyDocument": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Action": "execute-api:Invoke",
                    "Effect": "Allow",
                    "Resource": event["methodArn"]
                }]
            },
            "context": {"client_id": decoded_token.get("client_id", "unknown")}
        }

    except Exception as e:
        # Generate a unique correlation ID and timestamp for the error response
        correlation_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Prepare the error message and description
        error_message = str(e)
        description = f"Invalid value '{event.get('authorizationToken', '')}' for header 'Authorization'"

        # Return the error response with correlation ID and timestamp
        return {
            "principalId": "user",
            "policyDocument": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Action": "execute-api:Invoke",
                    "Effect": "Deny",
                    "Resource": event["methodArn"]
                }]
            },
            "context": {
                "error": json.dumps({
                    "code": 400,
                    "message": "BAD_REQUEST",
                    "description": description,
                    "correlationId": correlation_id,
                    "dateTime": timestamp
                })
            }
        }
