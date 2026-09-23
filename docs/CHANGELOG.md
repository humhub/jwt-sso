Changelog
=========

1.1.5 (September 23, 2026)
--------------------------

- Fix: Accept the `supportedAlgorithms` config key of versions before 1.1.4 again, which caused an `UnknownPropertyException` on the login page since 1.1.4
- Fix: Use the `firebase/php-jwt` library shipped with the core instead of the outdated bundled copy, which caused "Algorithm not allowed" on every JWT login since 1.1.4 (note: php-jwt 7 shipped with core 1.18.6+ requires HMAC keys of at least 32 bytes for HS256, 48 for HS384 and 64 for HS512)

1.1.4 (September 8, 2026)
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
