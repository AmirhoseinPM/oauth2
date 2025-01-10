openId configuration request:
    http://localhost:8080/.well-known/openid-configuration
response:
    {
     "issuer": "http://localhost:8080",
     "authorization_endpoint":
     "http://localhost:8080/oauth2/authorize",
     "token_endpoint": "http://localhost:8080/oauth2/token",
     "token_endpoint_auth_methods_supported": [
     "client_secret_basic",
     "client_secret_post",
     "client_secret_jwt",
     "private_key_jwt"
     ],
      "jwks_uri": "http://localhost:8080/oauth2/jwks",
      "userinfo_endpoint": "http://localhost:8080/userinfo",
      "response_types_supported": [
      "code"
      ],
      "grant_types_supported": [
      "authorization_code",
      "client_credentials",
      "refresh_token"
      ],
      "revocation_endpoint": "http://localhost:8080/oauth2/revoke",
      "revocation_endpoint_auth_methods_supported": [
      "client_secret_basic",
      "client_secret_post",
      "client_secret_jwt",
      "private_key_jwt"
      ],
      "introspection_endpoint":
      "http://localhost:8080/oauth2/introspect",
      "introspection_endpoint_auth_methods_supported": [
      "client_secret_basic",
      "client_secret_post",
      "client_secret_jwt",
      "private_key_jwt"
      ],
      "subject_types_supported": [
      "public"
      ],
      "id_token_signing_alg_values_supported": [
      "RS256"
      ],
      "scopes_supported": [
      "openid"
      ]
     }
-------------------------------
authorization code request:
    http://localhost:8080/oauth2/authorize?
    response_type=code&
    client_id=client&
    scope=openid&
    redirect_uri=https://www.manning.com/authorized&
    code_challenge=QYPAZ5NU8yvtlQ9erXrUYR-T5AGCjCF47vN-KsaI2A8&
    code_challenge_method=S256

redirect to https://www.manning.com/authorized with "code" that used in token request

token request needs authentication with HTTP Basic with the client ID and secret:
    curl -X POST 'http://localhost:8080/oauth2/token?
    client_id=client&
    redirect_uri=https://www.manning.com/authorized&
    grant_type=authorization_code&
    code=ao2oz47zdM0D5gbAqtZVB…
    code_verifier=qPsH306-… \
    --header 'Authorization: Basic Y2xpZW50OnNlY3JldA=='
* Authorization: Basic + Base64.encode(username + ":" + password)

returned:
    {
     "access_token": "eyJraWQiOiI4ODlhNGFmO…",
     "scope": "openid",
     "id_token": "eyJraWQiOiI4ODlhNGFmOS1…",
     "token_type": "Bearer",
     "expires_in": 299
    }
----------------------------------

The code verifier is a random 32-byte piece of data. To make it easy to transfer through a
HTTP request, this data needs to be Base64 encoded using an URL encoder and without
padding. The next code snippet shows how to do that in Java:

    SecureRandom secureRandom = new SecureRandom();
    byte [] code = new byte[32];
    secureRandom.nextBytes(code);
    String codeVerifier = Base64.getUrlEncoder()
     .withoutPadding()
     .encodeToString(code);

Once you have the code verifier, you use a hash function to generate the challenge. The
next code snippet shows how to create the challenge using the SHA-256 hash function.
As with the verifier, you need to use Base64 to change the byte array into a String value,
making it easier to transfer through the HTTP request:

    MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
    byte [] digested = messageDigest.digest(verifier.getBytes());
    String codeChallenge = Base64.getUrlEncoder()
     .withoutPadding()
     .encodeToString(digested);

-----------------------------------
CLIENT_CREDENTIALS:

    curl -X POST 'http://localhost:8080/oauth2/token?
    grant_type=client_credentials&
    scope=CUSTOM' \
    --header 'Authorization: Basic Y2xpZW50OnNlY3JldA=='

returned:
    {
     "access_token": "eyJraWQiOiI4N2E3YjJiNS…",
     "scope": "CUSTOM",
     "token_type": "Bearer",
     "expires_in": 300
    }

-------------------------------------
OPAQUE token: does not hold data, shorter than JWT

    curl -X POST 'http://localhost:8080/oauth2/token?
    grant_type=client_credentials&
    scope=CUSTOM' \
    --header 'Authorization: Basic Y2xpZW50OnNlY3JldA=='

returned:
    {
     "access_token": "iED8-...",
     "scope": "CUSTOM",
     "token_type": "Bearer",
     "expires_in": 299
    }

introspect data using token

    curl -X POST 'http://localhost:8080/oauth2/introspect?token=iED8-…' \
    --header 'Authorization: Basic Y2xpZW50OnNlY3JldA=='

returned:
    {
     "active": true,
     "sub": "client",
     "aud": [
     "client"
     ],
     "nbf": 1682941720,
     "scope": "CUSTOM",
     "iss": "http://localhost:8080",
     "exp": 1682942020,
     "iat": 1682941720,
     "jti": "ff14b844-1627-4567-8657-bba04cac0370",
     "client_id": "client",
     "token_type": "Bearer"
    }

If the token doesn’t exist or has expired:

{
 "active": false,
}
---------------------------------------------
Revoking tokens
Suppose you discover a token has been stolen. How could you make a token invalid for
use?
    curl -X POST 'http://localhost:8080/oauth2/revoke?token=N7BruErWm-44-…' \
    --header 'Authorization: Basic Y2xpZW50OnNlY3JldA=='
    