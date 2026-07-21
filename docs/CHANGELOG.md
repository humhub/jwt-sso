Changelog
=========

1.2.0 (Unreleased)
-------------------------

- Enh: Require core 1.19 (UserSource refactor).
- Enh: Add Codeception unit test suite (`JwtAuthTest`, `JwtUserSourceTest`) and
  the four shared `module-coding-standards` workflows (master / develop /
  next / min-version) so the module runs on CI on every push and weekly
  against all supported core branches.
- Enh: Manual rewritten — documents `provideUserSource`, the configurable
  `JwtUserSource` options, and the migration path from `JWTPrimary`.
- Enh: JWT AuthClient now extends `yii\authclient\BaseClient` directly and
  implements the new `CustomAuth` interface (`handleAuthRequest(): ?Response`),
  replacing the removed `humhub\modules\user\authclient\BaseClient` and the
  deprecated `StandaloneAuthClient` marker. The previous `authAction()` body
  moved to `handleAuthRequest()` — return `null` on success, AuthAction calls
  `authSuccess()` automatically.
- Enh: New opt-in `JwtUserSource` — enable via
  `'modules' => ['jwt-sso' => ['provideUserSource' => true]]` to make JWT-issued
  users their own `user_source = 'jwt'` and lock the configured managed
  attributes (defaults to `email` and `username`, configurable on the source).
  Replaces the legacy `JWTPrimary` semantics; the option is off by default to
  keep existing installs on `LocalUserSource` until admins are ready to migrate.
- Breaking: Dropped the deprecated `PrimaryClient` / `AutoSyncUsers` /
  `SyncAttributes` marker interfaces from `JWTPrimary`. Core 1.19 no longer
  reads them, so the class is now a slim, deprecated subclass of `JWT`. Existing
  `authClientCollection` configs of the form `'class' => JWTPrimary::class`
  keep working without code changes — to restore primary-style behaviour,
  enable `provideUserSource`.
- Note: User data is not auto-migrated — pre-1.19 users with `auth_mode = 'jwt'`
  end up with `user_source = 'local'` after the core upgrade (no `user_auth`
  row for the JWT identity). To keep them logging in via JWT on a system that
  enabled `provideUserSource`, either (a) add `'jwt'` to the local source's
  allowed clients via
  `'userSourceCollection' => ['userSources' => ['local' => ['allowedAuthClientIds' => ['local', 'jwt']]]]`
  or (b) backfill `user.user_source = 'jwt'` for the affected users via SQL.

1.1.4 (Unreleased)
-------------------------

- Enh: Use PHP CS Fixer
- Fix #9: Adjust JWT client to use new JWT package version

1.1.3 (November 23, 2023)
-------------------------

- Enh: Fixed Login Issue with `JWTPrimary` AuthClient

1.1.1 (June 14, 2023)
--------------------

- Enh: Added `JWTPrimary` AuthClient for auto synced users

1.1.0 (June 1, 2023)
--------------------

- Enh: Changed since v1.14 deprecated method 'AuthClientHelpers'
- Enh: Added option to bypass forced JWT login

1.0.1 (March 30, 2020)
-------------------------

- Enh: Documentation updates

1.0.0 (November 6, 2019)
-------------------------

- Enh: Initial commit of standalone version
