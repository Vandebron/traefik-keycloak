# Traefik Keycloak Plugin

** THIS IS A WORK IN PROGRESS AND IS NOT PRODUCTION READY**

This is a plugin that integrates Keycloak with Traefik and adds Headers with
Authenticated User information to the request.

This plugin only works with token signed by one of the certificates in the
keycloak JWK endpoint:
```
https://<keycloak>/auth/realms/<realm>/protocol/openid-connect/certs
```

If the token is signed by one of Keycloaks internal certificates, the plugin
will will show the user as unauthenticated.


**NOTE:** Traefik requires plugins to do vendoring, do to the custom
interpreter that they use

## Configuration

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: authenticator
  namespace: traefik
spec:
    plugin:
        authenticator:
            keycloak: https://<keycloak_url>/
            excludeClaims:
             - iss
```

## To Run Tests

```bash
go test -v ./...
```

## Local Dev Environment

There is a local development environment that you can run by running the
following

```bash
docker compose up
```

This will start a local Traefik instance with the the plugin installed and some
configuration (mainly pointing to our test keycloak instance). If you get
a token from the Test Keycloak instances and add it to the request, you will 
see the headers added to the request.


**Note**: All the headers with the `X-Auth-` prefix are added by the plugin.


fetching token:

```bash
curl --request POST \
  --url 'https://<keycloak>/realms/<realm>/protocol/openid-connect/token' \
  --header 'content-type: application/x-www-form-urlencoded' \
  --data grant_type=password \
  --data 'username=<username>' \
  --data 'password=<password>' \
  --data 'client_id=<client_id>'
```

Examples without a token:

```bash
curl http://<httpbin-url>/headers
{
  "headers": {
    ...
    "X-Auth-Unauthenticated": [
      "true"
    ],
    ...
  }
```

Examples with a token (Note we still pass the `Authorization` header to the
service):

```bash
curl http://<httpbin-url>/headers -H "Authorization Bearer $TOKEN"
{
  "headers": {
    "Authorization": [
        "Bearer $TOKEN"
    ],
    ...
    "X-Auth-Allowed-Origins": [
      "*"
    ],
    "X-Auth-Auth_time": [
      "1.74480087e+09"
    ],
    "X-Auth-Email": [
      "example-user@gmail.com"
    ],
    "X-Auth-Email_verified": [
      "true"
    ],
    "X-Auth-Exp": [
      "1.744873308e+09"
    ],
    "X-Auth-Iat": [
      "1.744872408e+09"
    ],
    "X-Auth-Jti": [
      "00000000-0000-0000-000000000000"
    ],
    "X-Auth-Nonce": [
      "00000000-0000-0000-000000000000"
    ],
    "X-Auth-Preferred_username": [
      "example-user"
    ],
    "X-Auth-Scope": [
      "openid profile email"
    ],
    "X-Auth-Sid": [
      "00000000-0000-0000-000000000000"
    ],
    "X-Auth-Sub": [
      "00000000-0000-0000-000000000000"
    ],
    "X-Auth-Typ": [
      "Bearer"
    ],
    ...
  }
}

```


