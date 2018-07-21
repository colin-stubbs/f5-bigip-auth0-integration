# F5 BIG-IP Auth0 Integration via OAuth 2.0/OpenID Connect

Configuration templates/scripts/iRules/sample F5 BIG-IP APM policy to utilise Auth0 via OAuth/OpenID Connect

# Using

Head to the [wiki](https://github.com/colin-stubbs/f5-bigip-auth0-integration/wiki) which provides detailed instructions on deployment options.

# Meh, just tell me what's in this repo?

1. iApp for F5 BIG-IP v13.1.0+ - it's [this file](https://github.com/colin-stubbs/f5-bigip-auth0-integration/blob/master/colin-stubbs.auth0-oauth-openid-client.tmpl)
   1. NOTE: The iApp will not create or modify a virtual server for you. Create it manually or use the official F5 [HTTP Applications iApp](https://f5.com/solutions/deployment-guides/http-applications-release-candidate-iapp) and deployment guide to create your virtual server and attach the APM policy created by the iApp from this repo if you choose to use it.
2. Sample F5 BIG-IP APM Policies
   1. A basic policy that initiates auth and completes an OpenID UserInfo request - in [this file](https://github.com/colin-stubbs/f5-bigip-auth0-integration/blob/master/profile_Common_Auth0-Integration-Simple-Template.conf.tar.gz)
   2. A more complete policy that initiates auth, obtains and validates the access token as being a JWT with valid JWS, completes OpenID Connect UserInfo request and completes external scope validation request - in [this file](https://github.com/colin-stubbs/f5-bigip-auth0-integration/blob/master/profile_Common_Auth0-Integration-Full-Template.conf.tar.gz)
3. Sample iRule for dealing with F5 BIG-IP Bug ID#685888 which causes various characters returned by Auth0 to be escaped, the most annoying which are vertical bars/pipes "|" which BIG-IP converts to "\|" any time it sets/copies anything as a session variable. So the subject from your access/ID token etc which should be "auth0|UNIQUE_ID" becomes "auth0\|UNIQUE_ID". Various characters in links to the OpenID headshot/photo will also get escaped renderly the URL useless. - in [this file](https://github.com/colin-stubbs/f5-bigip-auth0-integration/blob/master/RULE-BIGIP-OAuth-Fixer-Upper.irule)
4. TMSH configuration template to create APM OAuth and SSO objects along with all dependencies - in [this file](https://github.com/colin-stubbs/f5-bigip-auth0-integration/blob/master/auth0_template.txt)
5. Sample shell scripts to quickly turn the TMSH configuration template into something useful for immediate merge into the running TMSH config

## NOTE: F5 BIG-IP Bugs Related to OAuth and OpenID Connect

There is many. I've moved the description for all of the issues I've encountered into the wiki [here](https://github.com/colin-stubbs/f5-bigip-auth0-integration/wiki/F5-BIGIP-Bugs)

## NOTE: Auth0 Instance Certificate Import

You can create/import certificates into BIGIP direct from a URL. Auth0 provides your instances cert in PEM format via the URL https://%{AUTH0_INSTANCE}%.auth0.com/pem

Example TMSH CLI command,
```
create sys file ssl-cert routedlogic.auth0.com source-path https://routedlogic.auth0.com/pem
```

This is the process that the iApp uses in order to download and install the certificate automatically.

## Simple Auth0 Authentication Policy Flow

Import [this file](https://github.com/colin-stubbs/f5-bigip-auth0-integration/blob/master/profile_Common_Auth0-Integration-Simple-Template.conf.tar.gz) into BIG-IP APM to build a policy based on this.

![Simple Policy Flow](https://github.com/colin-stubbs/f5-bigip-auth0-integration/blob/master/screenshots/Auth0-Integration-Simple-Template_Flow.png "Simple Policy Flow")

## Auth0 Authentication with Access Token/Scope Validation/API Query/SSO Policy Flow

Import [this file](https://github.com/colin-stubbs/f5-bigip-auth0-integration/blob/master/profile_Common_Auth0-Integration-Full-Template.conf.tar.gz) into BIG-IP APM to build a policy based on this.

![Full Policy Flow](https://github.com/colin-stubbs/f5-bigip-auth0-integration/blob/master/screenshots/Auth0-Integration-Full-Template_Flow.png "Full Policy Flow")

# EOF
