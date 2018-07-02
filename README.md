# F5 BIGIP Auth0 Integration via OAuth 2.0/OpenID Connect

Configuration templates/scripts/iRules/sample APM policy to utilise Auth0 via OAuth/OpenID Connect

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

APM does this with almost everything returned within OAuth tokens and it really shouldn't. For instance, in a typical Auth0 session the following escaped session variables wind up getting messed up at minimum:
* sub - auth0\\|ID which should be auth0|ID
* iss - https:\\/\\/org-id-thingy.auth0.com\\/ which should be https://org-id-thingy.auth0.com/
* picture - URL to Gravatar etc, forward slashes get escaped with backslash much like iss

The workaround described in Bug ID 685888 does not appear to work in this case as there does not appear to be any event that can be hooked during the APM policy "OAuth Client" macro running. It also appears to obtain two ID tokens at different points, so I'm unclear about what requests it's actually making to Auth0.

It also does not appear to be possible to use a second "OAuth Client" macro that *ONLY* performs a UserInfo request as APM errors.

### Example Log Entry

```
Jun 27 17:39:36 bigip1 err apmd[15175]: 01490290:3: /Common/Example1:Common:354989a6:/Common/bigip_as_saml_service_provider_act_oauth_client_ag: OAuth Client: failed for server '/Common/routedlogic.auth0.com' using 'authorization_code' grant type (client_id=Bf4zTpwzeBJ4EUI1VkzMUw44EqQwz2KG), error: UserInfo sub mismatch : UserInfo sub = (auth0|5b31da4b7871d50de046a068) ID token sub = (auth0\|5b31da4b7871d50de046a068)
```

### Work Around (Terrible Code) iRule

The work around iRule in Bug ID 685888 does not adequately deal with additional escape characters that may appear in thinks like the ID token subject. Auth0 in particular prefixes the subject with 'auth0|' which BIGIP escapes to 'auth0\\|', making the subject problematic for later use.

The following iRule can be used to fix various attributes within the ID token. Add more fixes in the string map if you find other cases where BIGIP escapes stuff out that you don't want escaped.

```
when ACCESS_POLICY_AGENT_EVENT {
  if { [ACCESS::policy agent_id] equals {FIX_ID_TOKEN} } {
    set debug_irules [ACCESS::session data get session.custom.oauth.debug]
    set id_token {}
    set fix_id_token_attribs [list email iss name nickname picture sub]

    catch { set id_token [ACCESS::session data get -secure session.oauth.client.last.id_token] }

    if { ${id_token} != {} } {
      if { ${debug_irules} equals {1} } { log local0. "DEBUG: fixing ID token content escape issues because Bug ID 685888" }
      foreach attrib ${fix_id_token_attribs} {
        set attrib_value [ACCESS::session data get session.oauth.client.last.id_token.${attrib}]
        if { ${attrib_value} != {} } {
          ACCESS::session data set session.oauth.client.last.id_token.${attrib} [string map { {\|} {|} {\\} {} } ${attrib_value}]
          if { ${debug_irules} equals {1} } { log local0. "DEBUG: fixed session.oauth.client.last.id_token.${attrib} was ${attrib_value} now [ACCESS::session data get session.oauth.client.last.id_token.${attrib}]" }
        }
      }
    }
  }
}
```

```
Jul  2 22:43:04 bigip1 info tmm[20638]: Rule /Common/RULE-Debug-OAuth-1 <ACCESS_POLICY_AGENT_EVENT>: DEBUG: fixed session.oauth.client.last.id_token.email was cstubbs@gmail.com now cstubbs@gmail.com
Jul  2 22:43:04 bigip1 info tmm[20638]: Rule /Common/RULE-Debug-OAuth-1 <ACCESS_POLICY_AGENT_EVENT>: DEBUG: fixed session.oauth.client.last.id_token.iss was https:\\/\\/routedlogic.auth0.com\\/ now https://routedlogic.auth0.com/
Jul  2 22:43:04 bigip1 info tmm[20638]: Rule /Common/RULE-Debug-OAuth-1 <ACCESS_POLICY_AGENT_EVENT>: DEBUG: fixed session.oauth.client.last.id_token.name was cstubbs@gmail.com now cstubbs@gmail.com
Jul  2 22:43:04 bigip1 info tmm[20638]: Rule /Common/RULE-Debug-OAuth-1 <ACCESS_POLICY_AGENT_EVENT>: DEBUG: fixed session.oauth.client.last.id_token.nickname was cstubbs now cstubbs
Jul  2 22:43:04 bigip1 info tmm[20638]: Rule /Common/RULE-Debug-OAuth-1 <ACCESS_POLICY_AGENT_EVENT>: DEBUG: fixed session.oauth.client.last.id_token.picture was https:\\/\\/s.gravatar.com\\/avatar\\/a17f567a5f1cc701585e3484c2bb2e40?s=480&r=pg&d=https%3A%2F%2Fcdn.auth0.com%2Favatars%2Fcs.png now https://s.gravatar.com/avatar/a17f567a5f1cc701585e3484c2bb2e40?s=480&r=pg&d=https%3A%2F%2Fcdn.auth0.com%2Favatars%2Fcs.png
Jul  2 22:43:04 bigip1 info tmm[20638]: Rule /Common/RULE-Debug-OAuth-1 <ACCESS_POLICY_AGENT_EVENT>: DEBUG: fixed session.oauth.client.last.id_token.sub was auth0\|5b31da4b7871d50de046a068 now auth0|5b31da4b7871d50de046a068
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
Authorization failed: user=https://localhost/mgmt/cm/system/authn/providers/tmos/1f44a60e-11a7-3c51-a49f-82983026b41b/users/c54e66d3-d6ed-328b-a002-f0a9a1cac0b6resource=/mgmt/tm/access/oidc/discover verb=GET uri:http://localhost:8100/mgmt/tm/access/oidc/discover referrer:https://192.168.1.245/tmui/tmui/accessctrl/oauth/app/ sender:10.1.2.34
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

## Form POST Method Failure @ /oauth/client/redirect

Auth0 has configurable response modes, e.g. query (parameters in URI), fragment (for browser based apps e.g. SPA's), and form_post for POST'ing back to your callback URL.

BIGIP *CAN* handle a POST but fails to actually handle a POST to /oauth/client/redirect properly.

It also fails badly by simply chopping the connection and failing to return anything to the client.

e.g. it seems to expect "code" to be a URI parameter at minimum.

Well done whoever coded that mess up.

Use the following iRule as a kludge for more shitty code. By sticking the code in the URI again this seems to indicate to the internal BIGIP OAuth code that it should now actually look at the POST payload and do useful things.

```
when HTTP_REQUEST {
  # work around for BIGIP OAuth client not being able to handle POST based callbacks. Because F5 BIGIP bugs.

  if { [HTTP::uri] starts_with {/oauth/client/redirect} and [string tolower [HTTP::method]] equals {post} } {
    set debug_irules [ACCESS::session data get session.custom.oauth.debug]

    if { [HTTP::header exists "Content-Length"] } {
      if { [HTTP::header "Content-Length"] > 1048000 }{
        set content_length 1048000
      } else {
        set content_length [HTTP::header "Content-Length"]
      }
    } else {
      set content_length 1048000
    }
    if { $content_length > 0 } {
      if { ${debug_irules} equals {1} } { log local0. "DEBUG: POST to [HTTP::host][HTTP::uri] with ${content_length} bytes" }
      HTTP::collect $content_length
    }
  }
}
when HTTP_REQUEST_DATA {
  if { ${debug_irules} equals {1} } { log local0. "DEBUG: POST to [HTTP::host][HTTP::uri] payload is '[HTTP::payload]'" }

  set kvps [split [HTTP::payload] &]

  if { [HTTP::uri] contains {?} } {
    set append_to_uri {}
  } else {
    set append_to_uri {?aza=aza}
  }
  foreach kvp ${kvps} {
    if { ${kvp} contains {=} } {
      set key [getfield ${kvp} "=" 1]
      set value [getfield ${kvp} "=" 2]
      switch ${key} {
        "state" -
        "code" {
          if { ${debug_irules} equals {1} } { log local0. "DEBUG: POST to [HTTP::host][HTTP::uri] adding param to URI ${key} = '$value'" }
          set append_to_uri "${append_to_uri}&${key}=${value}"
        }
        default {
          # do nothing or log as below, comment if not needed
          if { ${debug_irules} equals {1} } { log local0. "DEBUG: POST to [HTTP::host][HTTP::uri] param $key = '$value'" }
        }
      }
      unset key value
    }
  }

  # whack it all on the end of the URI
  HTTP::uri "[HTTP::uri]${append_to_uri}"

  unset kvp kvps append_to_uri
}
```

Example logs *BEFORE* iRule in use, as you can see ***SUPER MEGA AWESOMELY USEFUL*** debug logs.

```
Jul  2 22:56:10 bigip1 debug apmd[15183]: 01490266:7: /Common/webtop.lab.routedlogic.net:Common:aac97daf: ApmD.cpp: 'sendAccessPolicyResponse()': 2697: send 'redirect to EUIE' code, redirect URL="/routedlogic.auth0.com:443/authorize?client_id=Bf4zTpwzeBJ4EUI1VkzMUw44EqQwz2KG&redirect_uri=https%3A%2F%2Flab.routedlogic.net%2Foauth%2Fclient%2Fredirect&response_mode=form_post&response_type=code&scope=openid%20openid%20profile%20email%20offline_access&state=M4x_sF0kqWpOSnr1-3O4xA&nonce=5QOBeYzQs0UapkfgesEQpA"
Jul  2 22:56:10 bigip1 debug apmd[15183]: 01490266:7: /Common/webtop.lab.routedlogic.net:Common:aac97daf: ApmD.cpp: 'process_apd_request()': 1815:  ** done with the request processing **
Jul  2 22:56:29 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: AccessPolicyProcessor/AccessPolicyProcessor.cpp: 'runSessionCleaner()': 1819: tmm_is_down is 0
Jul  2 22:56:29 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: AccessPolicyProcessor/AccessPolicyProcessor.cpp: 'checkCatalogKey()': 271: Found Catalog at tmm.session.f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5, value 222222
Jul  2 22:56:29 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: modules/Authentication/Identity/ifmap_connection.cpp: 'ifmap_send_keep_alive()': 135: Found 0 IF-MAP connections
Jul  2 22:56:29 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: modules/Authentication/Crldp/CrldpCache.cpp: 'CrldpSweeper()': 93: Running CrldpSweeper
Jul  2 22:56:29 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: modules/Authentication/Crldp/CrldpCache.cpp: 'CrldpSweeper()': 102: No entries in CrldpTable
Jul  2 22:56:29 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: AccessPolicyProcessor/AccessPolicyProcessor.cpp: 'runSessionCleaner()': 1855: Running Session Cleaner ...
Jul  2 22:56:29 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: AccessPolicyProcessor/AccessPolicyProcessor.cpp: 'runSessionCleaner()': 1882: 2 sessions with timeout 360s
Jul  2 22:56:29 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: AccessPolicyProcessor/AccessPolicyProcessor.cpp: 'runSessionCleaner()': 1903: Done session cleaner (timeout=360)...
^C
[root@bigip1:Active:Standalone] ~ # tail /var/log/ltm | grep DEBUG
Jul  2 22:56:25 bigip1 info tmm1[20638]: Rule /Common/RULE-OAuth-Auth0-Form-POST-Fix <HTTP_REQUEST_DATA>: DEBUG: POST payload to lab.routedlogic.net/oauth/client/redirect is 'code=7bz3nqIxQff_7dzo&state=M4x_sF0kqWpOSnr1-3O4xA'
[root@bigip1:Active:Standalone] ~ #
```

Example logs *AFTER* iRule in use,

```
Jul  2 23:01:30 bigip1 debug apmd[15183]: 01490266:7: /Common/webtop.lab.routedlogic.net:Common:5ea6c317: ApmD.cpp: 'sendAccessPolicyResponse()': 2697: send 'redirect to EUIE' code, redirect URL="/routedlogic.auth0.com:443/authorize?client_id=Bf4zTpwzeBJ4EUI1VkzMUw44EqQwz2KG&redirect_uri=https%3A%2F%2Flab.routedlogic.net%2Foauth%2Fclient%2Fredirect&response_mode=form_post&response_type=code&scope=openid%20openid%20profile%20email%20offline_access&state=Zqa0mUrwD48k-0fWEGYk4w&nonce=bkw61Pdq6oFvAShBTIpD7Q"
Jul  2 23:01:30 bigip1 debug apmd[15183]: 01490266:7: /Common/webtop.lab.routedlogic.net:Common:5ea6c317: ApmD.cpp: 'process_apd_request()': 1815:  ** done with the request processing **
Jul  2 23:01:34 bigip1 notice tmm1[20638]: 01490538:5: tmm.session.58a322637a4d4_130ooooooooooooooo: Configuration snapshot deleted by Access.
Jul  2 23:01:34 bigip1 notice tmm[20638]: 01490538:5: tmm.session.58a322637a4d4_130ooooooooooooooo: Configuration snapshot deleted by Access.
Jul  2 23:01:40 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: ApmD.cpp: 'process_accept()': 1597: process_accept: queueing 94
Jul  2 23:01:40 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: ApmD.cpp: 'process_apd_request()': 1684: Request Received : 94
Jul  2 23:01:40 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: queue.cpp: 'setMarker()': 377: queue::setMarker: thread id 48000333178624, step 0, name = Profile, value = readFromSocket
Jul  2 23:01:40 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: HTTPParser.cpp: 'readFromSocket()': 159: bytes_received: 521, len: 521
Jul  2 23:01:40 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: HTTPParser.cpp: 'readFromSocket()': 181: First header received: POST /oauth/client/redirect?state=Zqa0mUrwD48k-0fWEGYk4w&code=GYmkulTwiVBYwgkV&aza=aza HTTP/1.1
Jul  2 23:01:40 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: HTTPParser.cpp: 'parseHttpRequestHeader()': 417: HTTP Method received: POST
Jul  2 23:01:40 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: HTTPParser.cpp: 'parseHttpRequestHeader()': 446: HTTP URI received: /oauth/client/redirect?state=Zqa0mUrwD48k-0fWEGYk4w&code=GYmkulTwiVBYwgkV&aza=aza
Jul  2 23:01:40 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: HTTPParser.cpp: 'parseHttpRequestHeader()': 491: HTTP major version received: 1
Jul  2 23:01:40 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: HTTPParser.cpp: 'parseHttpRequestHeader()': 492: HTTP minor version received: 1
Jul  2 23:01:40 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: HTTPParser.cpp: 'parseHttpGenericHeader()': 536: Header received, content-length: 50
Jul  2 23:01:40 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: HTTPParser.cpp: 'parseHttpGenericHeader()': 539: Header received, oauth-authorization-code(16)
Jul  2 23:01:40 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: HTTPParser.cpp: 'parseHttpGenericHeader()': 539: Header received, oauth-state-param(22)
Jul  2 23:01:40 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: HTTPParser.cpp: 'parseHttpGenericHeader()': 536: Header received, client-session-id: 995c973ef762fc0b4627e7fb5ea6c317
Jul  2 23:01:40 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: HTTPParser.cpp: 'parseHttpGenericHeader()': 539: Header received, session-key(32)
Jul  2 23:01:40 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: HTTPParser.cpp: 'parseHttpGenericHeader()': 539: Header received, profile-id(34)
Jul  2 23:01:40 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: HTTPParser.cpp: 'parseHttpGenericHeader()': 539: Header received, partition-id(6)
Jul  2 23:01:40 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: HTTPParser.cpp: 'parseHttpGenericHeader()': 536: Header received, traffic-id: 1
Jul  2 23:01:40 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: HTTPParser.cpp: 'parseHttpGenericHeader()': 539: Header received, session-id(8)
Jul  2 23:01:40 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: HTTPParser.cpp: 'parseHttpGenericHeader()': 539: Header received, snapshot-id(32)
Jul  2 23:01:40 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: HTTPParser.cpp: 'parseHttpGenericHeader()': 536: Header received, cmp-pu: 0
Jul  2 23:01:40 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: HTTPParser.cpp: 'parsePostParam()': 582: Param received, code(16)
Jul  2 23:01:40 bigip1 debug apmd[15183]: 01490000:7: memcache.c func: "mc_convert_session_var_to_mc_key()" line: 2652 Msg: Converted Var: session.oauth.client./Common/qgovcidmwrappedauthentication_act_oauth_client_ag_1_2.UserInfo to Session Var tmm.session.5ea6c317.session.oauth.client./Common/qgovcidmwrappedauthentication_act_oauth_client_ag_1_2.UserInfo
Jul  2 23:01:40 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: HTTPParser.cpp: 'parsePostParam()': 582: Param received, state(22)
Jul  2 23:01:40 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: HTTPParser.cpp: 'parsePostParam()': 582: Param received, state(22)
Jul  2 23:01:40 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: HTTPParser.cpp: 'parsePostParam()': 582: Param received, code(16)
Jul  2 23:01:40 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: HTTPParser.cpp: 'parsePostParam()': 582: Param received, aza(3)
Jul  2 23:01:40 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: ApmD.cpp: 'process_apd_request()': 1709: start processing of the access policy. Request received: Session_ID = "5ea6c317",Profile_ID = "/Common/webtop.lab.routedlogic.net" Traffic-group Id = "1", Request_From = "", Clientless_Mode = "",No_Inspection_Host = "", CMP_Process_Unit = "0, mc = 0x2ba7f2cd6620"
Jul  2 23:01:40 bigip1 debug apmd[15183]: 01490266:7: (null):Common:00000000: queue.cpp: 'setMarker()': 377: queue::setMarker: thread id 48000333178624, step 1, name = Profile, value = searchProfileList
```

Note the function name there? ... parsePostParam() ... looks like the code should be able handle POST normally but is not configured/written to actually do so, and is instead insisting on checking URI parameters for things it wants.

If you enable debugging by way of access session var session.custom.oauth.debug = 1 you should get something like this to help work out what's going on.

```
Jul  2 23:18:09 bigip1 info tmm[20638]: Rule /Common/RULE-OAuth-Auth0-Form-POST-Fix <HTTP_REQUEST>: DEBUG: POST to lab.routedlogic.net/oauth/client/redirect with 50 bytes
Jul  2 23:18:09 bigip1 info tmm[20638]: Rule /Common/RULE-OAuth-Auth0-Form-POST-Fix <HTTP_REQUEST_DATA>: DEBUG: POST to lab.routedlogic.net/oauth/client/redirect payload is 'code=Dsw_d90VwYWYjJQO&state=bj3XD-rG_jaIUzW3muHhBg'
Jul  2 23:18:09 bigip1 info tmm[20638]: Rule /Common/RULE-OAuth-Auth0-Form-POST-Fix <HTTP_REQUEST_DATA>: DEBUG:  to lab.routedlogic.net/oauth/client/redirect adding param to URI code = 'Dsw_d90VwYWYjJQO'
Jul  2 23:18:09 bigip1 info tmm[20638]: Rule /Common/RULE-OAuth-Auth0-Form-POST-Fix <HTTP_REQUEST_DATA>: DEBUG:  to lab.routedlogic.net/oauth/client/redirect adding param to URI state = 'bj3XD-rG_jaIUzW3muHhBg'
Jul  2 23:18:10 bigip1 info tmm[20638]: Rule /Common/RULE-Debug-OAuth-1 <ACCESS_POLICY_AGENT_EVENT>: DEBUG: fixing ID token content escape issues because Bug ID 685888
Jul  2 23:18:10 bigip1 info tmm[20638]: Rule /Common/RULE-Debug-OAuth-1 <ACCESS_POLICY_AGENT_EVENT>: DEBUG: fixed session.oauth.client.last.id_token.email was cstubbs@gmail.com now cstubbs@gmail.com
Jul  2 23:18:10 bigip1 info tmm[20638]: Rule /Common/RULE-Debug-OAuth-1 <ACCESS_POLICY_AGENT_EVENT>: DEBUG: fixed session.oauth.client.last.id_token.iss was https:\\/\\/routedlogic.auth0.com\\/ now https://routedlogic.auth0.com/
Jul  2 23:18:10 bigip1 info tmm[20638]: Rule /Common/RULE-Debug-OAuth-1 <ACCESS_POLICY_AGENT_EVENT>: DEBUG: fixed session.oauth.client.last.id_token.name was cstubbs@gmail.com now cstubbs@gmail.com
Jul  2 23:18:10 bigip1 info tmm[20638]: Rule /Common/RULE-Debug-OAuth-1 <ACCESS_POLICY_AGENT_EVENT>: DEBUG: fixed session.oauth.client.last.id_token.nickname was cstubbs now cstubbs
Jul  2 23:18:10 bigip1 info tmm[20638]: Rule /Common/RULE-Debug-OAuth-1 <ACCESS_POLICY_AGENT_EVENT>: DEBUG: fixed session.oauth.client.last.id_token.picture was https:\\/\\/s.gravatar.com\\/avatar\\/a17f567a5f1cc701585e3484c2bb2e40?s=480&r=pg&d=https%3A%2F%2Fcdn.auth0.com%2Favatars%2Fcs.png now https://s.gravatar.com/avatar/a17f567a5f1cc701585e3484c2bb2e40?s=480&r=pg&d=https%3A%2F%2Fcdn.auth0.com%2Favatars%2Fcs.png
Jul  2 23:18:10 bigip1 info tmm[20638]: Rule /Common/RULE-Debug-OAuth-1 <ACCESS_POLICY_AGENT_EVENT>: DEBUG: fixed session.oauth.client.last.id_token.sub was auth0\|5b31da4b7871d50de046a068 now auth0|5b31da4b7871d50de046a068
```

# EOF
