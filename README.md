# F5 BIGIP Auth0 Integration via OAuth 2.0/OpenID Connect

Configuration templates/scripts/iRules/https://github.com/colin-stubbs/f5-bigip-auth0-integrationsample APM policy to utilise Auth0 via OAuth/OpenID Connect

# Using

## Simple Auth0 Authentication

TBC - content will be up soon

## Auth0 Authentication with Access Token/Scope Validation/API Query

TBC - content will be up soon

# F5 BIGIP Bugs

All bugs experienced on the following BIGIP versions:
1. 13.1.0.7.0.0.1
2. 13.1.0.8.0.0.3

## OpenID Connect Userinfo Request Failures

***NOTE***: This matches Bug ID 685888 directly. Bug ID 685888 needs to be expanded in scope and treated as a more serious issue.

### Description

OpenID Connect Userinfo requests by F5 BIGIP APM fail as BIGIP compares the UserInfo subject (sub) against the subject (sub) previously extracted from the id_token. Because APM went and moronically inserted backslash escapes against the content from the id_token the sub values no longer match.

APM does this with almost everything returned within OAuth tokens and it really shouldn't. For instance, in a typical session the following escaped session variables wind up getting created:

The workaround described in Bug ID 685888 does not appear to work in this case.

### Example Log Entry
```
Jun 27 17:39:36 bigip1 err apmd[15175]: 01490290:3: /Common/Example1:Common:354989a6:/Common/bigip_as_saml_service_provider_act_oauth_client_ag: OAuth Client: failed for server '/Common/routedlogic.auth0.com' using 'authorization_code' grant type (client_id=Bf4zTpwzeBJ4EUI1VkzMUw44EqQwz2KG), error: UserInfo sub mismatch : UserInfo sub = (auth0|5b31da4b7871d50de046a068) ID token sub = (auth0\|5b31da4b7871d50de046a068)
```

## Incorrect Handling of JWS KID/X5T Base64 Encoding

Error Text
```
An error occurred:
General error: 01071c83:3: (/Common/auto_jwk_Test1) (/Common/auto_jwk_Test1_cert.crt) load failed due to x5tsha1 mismatch in statement [SET TRANSACTION END]
```

This fails with the default Auth0 /.well-known/openid-configuration and /.well-known/jwks.json content.

The x5t value in /.well-known/jwks.json is correct but BIGIP fails to parse/handle it against the certificate content.

The reason it does this is because the BIGIP implementation is expecting the X5T value to include base64 padding characters ('=' characters) which ***MUST NOT*** be used in the context of JWS's. This is why Auth0 does not have '=' characters in KID/X5T; they conform to the RFC spec.

BIGIP JWKS consumption implementation needs a way in which to validate X5T without requiring padding characters to exist, e.g. calculate base64 KID/X5T and remove '=' characters prior to comparison.

```
[DESKTOP] ➤ cat routedlogic.auth0.com.crt
-----BEGIN CERTIFICATE-----
MIIDBTCCAe2gAwIBAgIJEg+Qd7QtWdkcMA0GCSqGSIb3DQEBCwUAMCAxHjAcBgNV
BAMTFXJvdXRlZGxvZ2ljLmF1dGgwLmNvbTAeFw0xODA2MjYwMjQwMDFaFw0zMjAz
MDQwMjQwMDFaMCAxHjAcBgNVBAMTFXJvdXRlZGxvZ2ljLmF1dGgwLmNvbTCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANzwQGQ8xvC2eOBwmrhXclfj+1Ri
ykSPT6Il5oAft8g0JlWoVLa8rlNriMBeJ/vLtd0eVlVL+pPXW2Ih7veVOWbEJo8W
xcd1E9Q4Qk4h94+INNAFfZGfwiZIv2gYLTv9zydpP/dGc+De/HqKoh5w5Ytn6ME0
7NFz1FV+VoV6E2fab6PGHXygwZ5N7SNFWYOiDpwbrt+m0KiuuGSc6qO+U7IXxX1l
UQcodBB1WdZQAn7r6y5Q/eZvwhLhMWZBs5h0ZksZ1kmwTvuoiDuv0FyqxbSOv/Yi
JUYGEAxkA8ODt1NF0loGiPEG546vqOJ78cPGWZeTsMnYhyvCzl8Sq0vj39kCAwEA
AaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUHcQq3WZOgbL4i8zSaakb
ECM9ciAwDgYDVR0PAQH/BAQDAgKEMA0GCSqGSIb3DQEBCwUAA4IBAQCDq4DcWjgm
MUGs+GOdimimmGwmntFlcyoBnYEe4axVxJDl3xfE1fW67mPdXZM0NWgjv5o8XVxz
7rQXHEwQbJsNTxaGCerFN4ZrpmN/vOPonNHRzfhz90X+a5frxdz2bqEPJhb8aX3+
OpjMWgmBAKAT/ngyIh6u9sdF75sU4AAGSljLJus5UXG+l3z6OK8HdAlp2EbYvqji
XAK9OsgRxWYJner8Fhc9cq4GvjODJh4PSS5gSLbkH0XbJabzpr3zLbi/16N5s66i
nSATFXxVKgfH8/aIHWy7drddqtRUJrQTSl130EOnoS/YS2lGEzrkV6coTtssSrkQ
XGCxVyi+LgPz
-----END CERTIFICATE-----
[DESKTOP] ➤ openssl x509 -fingerprint -noout -in routedlogic.auth0.com.crt
SHA1 Fingerprint=56:EA:EE:87:DC:F0:F1:C3:60:1F:FA:FD:2F:00:B9:79:76:E8:30:1D
[DESKTOP] ➤ openssl x509 -fingerprint -noout -in routedlogic.auth0.com.crt | cut -f2 -d'=' | sed 's/://g'
56EAEE87DCF0F1C3601FFAFD2F00B97976E8301D
[DESKTOP] ➤ echo -n '56EAEE87DCF0F1C3601FFAFD2F00B97976E8301D' | base64
NTZFQUVFODdEQ0YwRjFDMzYwMUZGQUZEMkYwMEI5Nzk3NkU4MzAxRA==
[DESKTOP] ➤
```

Formatted JWKS content from: https://routedlogic.auth0.com/.well-known/jwks.json

```
{
  "keys": [
    {
      "alg": "RS256",
      "kty": "RSA",
      "use": "sig",
      "x5c": [
        "MIIDBTCCAe2gAwIBAgIJEg+Qd7QtWdkcMA0GCSqGSIb3DQEBCwUAMCAxHjAcBgNVBAMTFXJvdXRlZGxvZ2ljLmF1dGgwLmNvbTAeFw0xODA2MjYwMjQwMDFaFw0zMjAzMDQwMjQwMDFaMCAxHjAcBgNVBAMTFXJvdXRlZGxvZ2ljLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANzwQGQ8xvC2eOBwmrhXclfj+1RiykSPT6Il5oAft8g0JlWoVLa8rlNriMBeJ/vLtd0eVlVL+pPXW2Ih7veVOWbEJo8Wxcd1E9Q4Qk4h94+INNAFfZGfwiZIv2gYLTv9zydpP/dGc+De/HqKoh5w5Ytn6ME07NFz1FV+VoV6E2fab6PGHXygwZ5N7SNFWYOiDpwbrt+m0KiuuGSc6qO+U7IXxX1lUQcodBB1WdZQAn7r6y5Q/eZvwhLhMWZBs5h0ZksZ1kmwTvuoiDuv0FyqxbSOv/YiJUYGEAxkA8ODt1NF0loGiPEG546vqOJ78cPGWZeTsMnYhyvCzl8Sq0vj39kCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUHcQq3WZOgbL4i8zSaakbECM9ciAwDgYDVR0PAQH/BAQDAgKEMA0GCSqGSIb3DQEBCwUAA4IBAQCDq4DcWjgmMUGs+GOdimimmGwmntFlcyoBnYEe4axVxJDl3xfE1fW67mPdXZM0NWgjv5o8XVxz7rQXHEwQbJsNTxaGCerFN4ZrpmN/vOPonNHRzfhz90X+a5frxdz2bqEPJhb8aX3+OpjMWgmBAKAT/ngyIh6u9sdF75sU4AAGSljLJus5UXG+l3z6OK8HdAlp2EbYvqjiXAK9OsgRxWYJner8Fhc9cq4GvjODJh4PSS5gSLbkH0XbJabzpr3zLbi/16N5s66inSATFXxVKgfH8/aIHWy7drddqtRUJrQTSl130EOnoS/YS2lGEzrkV6coTtssSrkQXGCxVyi+LgPz"
      ],
      "n": "3PBAZDzG8LZ44HCauFdyV-P7VGLKRI9PoiXmgB-3yDQmVahUtryuU2uIwF4n-8u13R5WVUv6k9dbYiHu95U5ZsQmjxbFx3UT1DhCTiH3j4g00AV9kZ_CJki_aBgtO_3PJ2k_90Zz4N78eoqiHnDli2fowTTs0XPUVX5WhXoTZ9pvo8YdfKDBnk3tI0VZg6IOnBuu36bQqK64ZJzqo75TshfFfWVRByh0EHVZ1lACfuvrLlD95m_CEuExZkGzmHRmSxnWSbBO-6iIO6_QXKrFtI6_9iIlRgYQDGQDw4O3U0XSWgaI8Qbnjq-o4nvxw8ZZl5OwydiHK8LOXxKrS-Pf2Q",
      "e": "AQAB",
      "kid": "NTZFQUVFODdEQ0YwRjFDMzYwMUZGQUZEMkYwMEI5Nzk3NkU4MzAxRA",
      "x5t": "NTZFQUVFODdEQ0YwRjFDMzYwMUZGQUZEMkYwMEI5Nzk3NkU4MzAxRA"
    }
  ]
}
```

Note the lack of '=' characters in the kid/x5t values.

For more info on how/why padding is supposed to be omitted refer to the relevant RFC's, e.g. JSON Web Signature (JWS) as defined by RFC 7515

[https://tools.ietf.org/html/rfc7515](https://tools.ietf.org/html/rfc7515)

![Error Message Screenshot](https://github.com/colin-stubbs/f5-bigip-auth0-integration/blob/master/bigip_oauth_issue_2.png "Issue 2 Screenshot")

## BIGIP WebUI Permission Errors

Users with read/write permissions restricted to a specific permission set, and possibly when restricted to a specific partition, will have trouble listing OAuth Provider configurations with the BIGIP webUI.

Manual requests against the TMUI API, by the same user, using their existing X-F5-Auth-Token are still possible in order to manually delete and modify objects that have already been created.

e.g. DELETE method to https://A.B.C.D/mgmt/tm/apm/aaa/oauth-provider/~PARTITION~Object_Name

Error Text
```
An error occurred:
Authorization failed: user=https://localhost/mgmt/cm/system/authn/providers/tmos/1f44a60e-11a7-3c51-a49f-82983026b41b/users/c54e66d3-d6ed-328b-a002-f0a9a1cac0b6resource=/mgmt/tm/access/oidc/discover verb=GET uri:http://localhost:8100/mgmt/tm/access/oidc/discover referrer:https://192.168.12.84/tmui/tmui/accessctrl/oauth/app/ sender:10.91.78.26
```

Screenshot
![Error Message Screenshot](https://github.com/colin-stubbs/f5-bigip-auth0-integration/blob/master/bigip_oauth_issue_3.png "Issue 3 Screenshot")

## TMSH Config Merge Issues

tmsh produces errors as it doesn't know how to merge changes against an existing object.

It trips on both:
1. apm oauth jwk-config objects
2. apm oauth jwt-config objects

Example CLI
```
[root@bigip1:Active:Standalone] tmp # tmsh load sys config file merge.txt merge
Loading configuration...
  /shared/tmp/merge.txt
01071cad:3: All the JWK configs in a JWT config must have unique key-id for each key-type. The key-id 'NTZFQUVFODdEQ0YwRjFDMzYwMUZGQUZEMkYwMEI5Nzk3NkU4MzAxRA' for key-type 'rsa' is already present in JWT config '/Common/routedlogic.auth0.com'.
Unexpected Error: Loading configuration process failed.
[root@bigip1:Active:Standalone] tmp # vim auth0_template.txt
[root@bigip1:Active:Standalone] tmp # vim merge.txt
[root@bigip1:Active:Standalone] tmp # vim merge.txt
[root@bigip1:Active:Standalone] tmp # tmsh load sys config file merge.txt merge
Loading configuration...
  /shared/tmp/merge.txt
01071cad:3: All the JWK configs in a JWT config must have unique key-id for each key-type. The key-id 'NTZFQUVFODdEQ0YwRjFDMzYwMUZGQUZEMkYwMEI5Nzk3NkU4MzAxRA' for key-type 'rsa' is already present in JWT config '/Common/routedlogic.auth0.com'.
Unexpected Error: Loading configuration process failed.
[root@bigip1:Active:Standalone] tmp # vim merge.txt
[root@bigip1:Active:Standalone] tmp # tmsh load sys config file merge.txt merge
Loading configuration...
  /shared/tmp/merge.txt
[root@bigip1:Active:Standalone] tmp #
[root@bigip1:Active:Standalone] tmp # sh auth0_template.sh  > merge.txt
[root@bigip1:Active:Standalone] tmp # tmsh load sys config file merge.txt merge
Loading configuration...
  /shared/tmp/merge.txt
01071cad:3: All the JWK configs in a JWT config must have unique key-id for each key-type. The key-id 'NTZFQUVFODdEQ0YwRjFDMzYwMUZGQUZEMkYwMEI5Nzk3NkU4MzAxRA' for key-type 'rsa' is already present in JWT config '/Common/routedlogic.auth0.com'.
Unexpected Error: Loading configuration process failed.
[root@bigip1:Active:Standalone] tmp # head merge.txt
apm oauth jwk-config routedlogic.auth0.com {
    alg-type RS256
    cert routedlogic.auth0.com.crt
    cert-chain routedlogic.auth0.com.crt
    cert-thumbprint-sha1 Vuruh9zw8cNgH_r9LwC5eXboMB0
    cert-thumbprint-sha256 VmXvTWLpz5T5rVIKjJkkQrgGDc3G4g9_WZQPoF5wObA
    key-id NTZFQUVFODdEQ0YwRjFDMzYwMUZGQUZEMkYwMEI5Nzk3NkU4MzAxRA
    modulus 3PBAZDzG8LZ44HCauFdyV-P7VGLKRI9PoiXmgB-3yDQmVahUtryuU2uIwF4n-8u13R5WVUv6k9dbYiHu95U5ZsQmjxbFx3UT1DhCTiH3j4g00AV9kZ_CJki_aBgtO_3PJ2k_90Zz4N78eoqiHnDli2fowTTs0XPUVX5WhXoTZ9pvo8YdfKDBnk3tI0VZg6IOnBuu36bQqK64ZJzqo75TshfFfWVRByh0EHVZ1lACfuvrLlD95m_CEuExZkGzmHRmSxnWSbBO-6iIO6_QXKrFtI6_9iIlRgYQDGQDw4O3U0XSWgaI8Qbnjq-o4nvxw8ZZl5OwydiHK8LOXxKrS-Pf2Q
    public-exponent AQAB
    x5c { MIIDBTCCAe2gAwIBAgIJEg+Qd7QtWdkcMA0GCSqGSIb3DQEBCwUAMCAxHjAcBgNVBAMTFXJvdXRlZGxvZ2ljLmF1dGgwLmNvbTAeFw0xODA2MjYwMjQwMDFaFw0zMjAzMDQwMjQwMDFaMCAxHjAcBgNVBAMTFXJvdXRlZGxvZ2ljLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANzwQGQ8xvC2eOBwmrhXclfj+1RiykSPT6Il5oAft8g0JlWoVLa8rlNriMBeJ/vLtd0eVlVL+pPXW2Ih7veVOWbEJo8Wxcd1E9Q4Qk4h94+INNAFfZGfwiZIv2gYLTv9zydpP/dGc+De/HqKoh5w5Ytn6ME07NFz1FV+VoV6E2fab6PGHXygwZ5N7SNFWYOiDpwbrt+m0KiuuGSc6qO+U7IXxX1lUQcodBB1WdZQAn7r6y5Q/eZvwhLhMWZBs5h0ZksZ1kmwTvuoiDuv0FyqxbSOv/YiJUYGEAxkA8ODt1NF0loGiPEG546vqOJ78cPGWZeTsMnYhyvCzl8Sq0vj39kCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUHcQq3WZOgbL4i8zSaakbECM9ciAwDgYDVR0PAQH/BAQDAgKEMA0GCSqGSIb3DQEBCwUAA4IBAQCDq4DcWjgmMUGs+GOdimimmGwmntFlcyoBnYEe4axVxJDl3xfE1fW67mPdXZM0NWgjv5o8XVxz7rQXHEwQbJsNTxaGCerFN4ZrpmN/vOPonNHRzfhz90X+a5frxdz2bqEPJhb8aX3+OpjMWgmBAKAT/ngyIh6u9sdF75sU4AAGSljLJus5UXG+l3z6OK8HdAlp2EbYvqjiXAK9OsgRxWYJner8Fhc9cq4GvjODJh4PSS5gSLbkH0XbJabzpr3zLbi/16N5s66inSATFXxVKgfH8/aIHWy7drddqtRUJrQTSl130EOnoS/YS2lGEzrkV6coTtssSrkQXGCxVyi+LgPz }
[root@bigip1:Active:Standalone] tmp # tmsh list apm oauth jwk-config routedlogic.auth0.com
apm oauth jwk-config routedlogic.auth0.com {
    alg-type RS256
    cert routedlogic.auth0.com.crt
    cert-thumbprint-sha1 Vuruh9zw8cNgH_r9LwC5eXboMB0
    cert-thumbprint-sha256 VmXvTWLpz5T5rVIKjJkkQrgGDc3G4g9_WZQPoF5wObA
    key-id NTZFQUVFODdEQ0YwRjFDMzYwMUZGQUZEMkYwMEI5Nzk3NkU4MzAxRA
    modulus 3PBAZDzG8LZ44HCauFdyV-P7VGLKRI9PoiXmgB-3yDQmVahUtryuU2uIwF4n-8u13R5WVUv6k9dbYiHu95U5ZsQmjxbFx3UT1DhCTiH3j4g00AV9kZ_CJki_aBgtO_3PJ2k_90Zz4N78eoqiHnDli2fowTTs0XPUVX5WhXoTZ9pvo8YdfKDBnk3tI0VZg6IOnBuu36bQqK64ZJzqo75TshfFfWVRByh0EHVZ1lACfuvrLlD95m_CEuExZkGzmHRmSxnWSbBO-6iIO6_QXKrFtI6_9iIlRgYQDGQDw4O3U0XSWgaI8Qbnjq-o4nvxw8ZZl5OwydiHK8LOXxKrS-Pf2Q
    public-exponent AQAB
    x5c { MIIDBTCCAe2gAwIBAgIJEg+Qd7QtWdkcMA0GCSqGSIb3DQEBCwUAMCAxHjAcBgNVBAMTFXJvdXRlZGxvZ2ljLmF1dGgwLmNvbTAeFw0xODA2MjYwMjQwMDFaFw0zMjAzMDQwMjQwMDFaMCAxHjAcBgNVBAMTFXJvdXRlZGxvZ2ljLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANzwQGQ8xvC2eOBwmrhXclfj+1RiykSPT6Il5oAft8g0JlWoVLa8rlNriMBeJ/vLtd0eVlVL+pPXW2Ih7veVOWbEJo8Wxcd1E9Q4Qk4h94+INNAFfZGfwiZIv2gYLTv9zydpP/dGc+De/HqKoh5w5Ytn6ME07NFz1FV+VoV6E2fab6PGHXygwZ5N7SNFWYOiDpwbrt+m0KiuuGSc6qO+U7IXxX1lUQcodBB1WdZQAn7r6y5Q/eZvwhLhMWZBs5h0ZksZ1kmwTvuoiDuv0FyqxbSOv/YiJUYGEAxkA8ODt1NF0loGiPEG546vqOJ78cPGWZeTsMnYhyvCzl8Sq0vj39kCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUHcQq3WZOgbL4i8zSaakbECM9ciAwDgYDVR0PAQH/BAQDAgKEMA0GCSqGSIb3DQEBCwUAA4IBAQCDq4DcWjgmMUGs+GOdimimmGwmntFlcyoBnYEe4axVxJDl3xfE1fW67mPdXZM0NWgjv5o8XVxz7rQXHEwQbJsNTxaGCerFN4ZrpmN/vOPonNHRzfhz90X+a5frxdz2bqEPJhb8aX3+OpjMWgmBAKAT/ngyIh6u9sdF75sU4AAGSljLJus5UXG+l3z6OK8HdAlp2EbYvqjiXAK9OsgRxWYJner8Fhc9cq4GvjODJh4PSS5gSLbkH0XbJabzpr3zLbi/16N5s66inSATFXxVKgfH8/aIHWy7drddqtRUJrQTSl130EOnoS/YS2lGEzrkV6coTtssSrkQXGCxVyi+LgPz }
}
[root@bigip1:Active:Standalone] tmp #
```
