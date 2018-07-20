# F5 BIG-IP Auth0 Integration via OAuth 2.0/OpenID Connect

Configuration templates/scripts/iRules/sample F5 BIG-IP APM policy to utilise Auth0 via OAuth/OpenID Connect

# Using

The wiki provides detailed instructions on deployment options.

## Auth0 Instance Certificate Import

You can create/import certificates into BIGIP direct from a URL. Auth0 provides your instances cert in PEM format via the URL https://%{AUTH0_INSTANCE}%.auth0.com/pem

Example TMSH CLI command,
```
create sys file ssl-cert routedlogic.auth0.com source-path https://routedlogic.auth0.com/pem
```

## Simple Auth0 Authentication

TBC - content will be up soon

![Simple Policy Flow](https://github.com/colin-stubbs/f5-bigip-auth0-integration/blob/master/screenshots/Auth0-Integration-Simple-Template_Flow.png "Simple Policy Flow")

## Auth0 Authentication with Access Token/Scope Validation/API Query/SSO

TBC - content will be up soon

![Full Policy Flow](https://github.com/colin-stubbs/f5-bigip-auth0-integration/blob/master/screenshots/Auth0-Integration-Full-Template_Flow.png "Full Policy Flow")

# EOF
