# Manual

## Installation and Configuration

JWT authentication is configured in HumHub's PHP config file (e.g. `protected/config/common.php`).
See the [HumHub admin docs](https://docs.humhub.org/docs/admin/advanced-configuration)
for general information about configuration files.

### Minimal example

```php
return [
    'components' => [
        'authClientCollection' => [
            'clients' => [
                'jwt' => [
                    'class' => 'humhub\modules\sso\jwt\authclient\JWT',
                    'sharedKey' => 'replace-with-a-long-random-secret',
                    'url' => 'https://broker.example.com/jwt/issue.php',
                ],
            ],
        ],
    ],
];
```

### All AuthClient options

| Option                | Type     | Default   | Description                                                                                              |
|-----------------------|----------|-----------|----------------------------------------------------------------------------------------------------------|
| `class`               | string   | —         | Always `humhub\modules\sso\jwt\authclient\JWT`.                                                          |
| `sharedKey`           | string   | —         | Shared secret used to verify the JWT signature.                                                          |
| `url`                 | string   | —         | URL of the JWT broker. Users are redirected here when no token is presented.                             |
| `supportedAlgorithm`  | string   | `HS256`   | JWT signing algorithm. Supported: `HS256`, `HS384`, `HS512`, `RS256`.                                    |
| `idAttribute`         | string   | `email`   | Claim used to match the HumHub user when no explicit `id` is in the payload (`email`, `username`, `guid`). |
| `leeway`              | int      | `60`      | Clock skew tolerance (seconds) for token validation.                                                     |
| `allowedIPs`          | array    | `[]`      | Restrict JWT access to specific IPs. Supports wildcards: `192.168.1.*`, `*`.                             |
| `autoLogin`           | bool     | `false`   | When the request IP matches `allowedIPs`, redirect to the broker automatically instead of showing the login form. |
| `title`               | string   | `JWT SSO` | Label shown on the login-page button (when `autoLogin` is off).                                          |

### Full configuration example

```php
'jwt' => [
    'class' => 'humhub\modules\sso\jwt\authclient\JWT',
    'sharedKey' => 'replace-with-a-long-random-secret',
    'url' => 'https://broker.example.com/jwt/issue.php',
    'title' => 'Company SSO Login',
    'autoLogin' => true,
    'allowedIPs' => ['192.168.69.1', '192.168.1.*'],
    'leeway' => 660,
    'supportedAlgorithm' => 'HS256',
],
```

## Auto Login

The JWT token must be supplied as the `jwt` query parameter on the login URL:

```
https://example.com/user/auth/login?jwt=eyJhbGciOi…
```

If `autoLogin` is enabled and the request IP matches `allowedIPs`, HumHub
redirects guests to the broker `url` instead of rendering the local login form.
Append `?noJwt=1` to the login URL to bypass the redirect (useful for admins
recovering local accounts).

## JWT Token Structure

The payload may carry any HumHub profile field (internal field name). Mapped
fields are written to the user profile on every login.

At least one of these claims must be present so the user can be matched:
`id`, `email`, `guid`, `username`.

```json
{
  "iss": "example",
  "iat": 1585585174,
  "guid": "unique.user.key",
  "username": "john.doe",
  "email": "john.doe@example.com",
  "firstname": "John",
  "lastname": "Doe",
  "city": "Munich"
}
```

The standard JWT meta-claims `iss`, `iat`, `jti` are stripped before mapping
to profile fields.

## User Source (`provideUserSource`)

Since HumHub 1.19 user provisioning lives on a *User Source*. The JWT module
ships an opt-in `JwtUserSource` that owns users created via JWT and locks the
attributes managed by the broker.

Enable it in `protected/config/common.php`:

```php
'modules' => [
    'jwt-sso' => [
        'provideUserSource' => true,
    ],
],
```

When enabled:

- New JWT users are stored with `user_source = 'jwt'` (instead of `local`).
- Configured `managedAttributes` are read-only in the user's profile — the
  broker is the source of truth.
- The `JwtUserSource` can be further configured under the
  `userSourceCollection` component (see below).

When **disabled** (the default) JWT users keep landing in `LocalUserSource`
and behave like locally-registered users — matching the pre-1.19 behaviour on
upgrade.

### Customising the `JwtUserSource`

```php
'components' => [
    'userSourceCollection' => [
        'userSources' => [
            'jwt' => [
                'class' => 'humhub\modules\sso\jwt\source\JwtUserSource',
                'title' => 'Company JWT',
                'managedAttributes' => ['email', 'username', 'firstname', 'lastname'],
                'approval' => true,
                'bypassApproval' => true,
            ],
        ],
    ],
],
```

| Option              | Type   | Default                 | Description                                                                                       |
|---------------------|--------|-------------------------|---------------------------------------------------------------------------------------------------|
| `title`             | string | `JWT SSO`               | Label shown in admin UI (user list, source filters).                                              |
| `managedAttributes` | array  | `['email', 'username']` | Profile fields the broker owns. Locked for the user and overwritten on every login.               |
| `approval`          | bool   | follows site default    | Whether new JWT users need admin approval before they can log in.                                 |
| `bypassApproval`    | bool   | `false`                 | Trust the JWT auth client so newly created JWT users skip approval even when `approval` is `true`.|

## Migrating from `JWTPrimary`

Before 1.19 the module shipped a `JWTPrimary` AuthClient that marked JWT as the
primary identity (auto-sync attributes, optional approval-bypass). The marker
interfaces it relied on were removed in core 1.19.

- **Existing configs keep working.** `JWTPrimary::class` still resolves and
  behaves like the regular `JWT` AuthClient.
- **To restore primary-style behaviour**, enable `provideUserSource` and
  configure the source as shown above.
- **Existing users are not auto-migrated.** Users created on a pre-1.19 install
  end up with `user_source = 'local'` after the upgrade and no `user_auth` row
  for the JWT identity. To keep them logging in via JWT once `provideUserSource`
  is enabled, do **one** of:
  - Allow the local source to accept the `jwt` auth client:
    ```php
    'components' => [
        'userSourceCollection' => [
            'userSources' => [
                'local' => [
                    'allowedAuthClientIds' => ['local', 'jwt'],
                ],
            ],
        ],
    ],
    ```
  - Or backfill the source column in SQL for the affected users:
    ```sql
    UPDATE user
       SET user_source = 'jwt'
     WHERE id IN (/* users you want to move under the JWT source */);
    ```

## Example Scripts

The directory `protected/modules/jwt-sso/examples/` contains reference
implementations for issuing JWT tokens:

- **`asp_ad`** — SSO via VBScript + NTLM.
- **`php`** — JWT token generation with the Firebase PHP library.
