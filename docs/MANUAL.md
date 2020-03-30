# Manual

## Installation and Configuration

To enable JWT authentication the HumHub configuration file must be modified.

More information about these configuration files can be found in [HumHub documentation](https://docs.humhub.org/docs/admin/advanced-configuration). 

Example configuration ``/protected/config/common.php``:
 
```php
return [
    // ...
    'components' => [
        // ...
        'authClientCollection' => [
            'clients' => [
                // ...
                'jwt' => [
                    // Begin of JWT configuration options

                    // Required: The JWT Class (do not modify)
                    'class' => 'humhub\modules\sso\jwt\authclient\JWT',
                
                    // Required: A shared secret key to sign the JWT token
                    'sharedKey' => 'XKqSoxWRcLVDtveMbhQ3oxgvogWT2ef3KpKLOF_gZgwTJyznr6UDi2SCWgSeaEUo5T1_bBYbR_blojv94Sr523zDQ_CzTETN4gMYyx6xU4hsF6HGnCdoFwmd9rOTY5MiIdGX1wdwP3FvpyS0bbmG17xfTtU87gySiQaJjQWq9J2SdLOu73xPej5l1k5BA2ab-taXogZi-STi1q30w0T0kU3SGJ-fYSZO5lGNI3pws313oh83Wby8IJxhS9GZjLjOHpMO7rveoUHE6cGOXm8SjuxsJTfChPl3sGhiA2Wc-cJ-uKaN37T7qQxKeZNjXFtNGTbXwOhXbtELP_ZUy66zPg',

                    // Required: The URL to redirect if JWT authentication is requested 
                    'url' => 'http://ntlm.example.com/jwtclient/index.php',                   

                    // Optional: Title of JWT Button (if autologin is disabled)
                    'title' => 'Company SSO Login',

                    // Optional: Automatic login, when allowed IP matches
                    'autoLogin' => true,

                    // Optional: Limit allowed JWT IPs
                    'allowedIPs' => ['192.168.69.1', '192.168.1.*'],

                    // Optional: Leeway (seconds) for token validation
                    'leeway' => 660,

                    // Optional: JWT algorithms
                    'supportedAlgorithms' => ['HS256']

                    // End of JWT configuration options
                ],
            ],
        ],
        // ...
    ],
    // ...
];
```

## Auto Login

The JWT token must be provided as query parameter ``jwt`` to the URL of the login page.

If your HumHub installation has Pretty URLs enabled, the URL should look like this:

https://example.com/user/auth/login?jwt=1234567890ABCDEFGH1234567890ABCDEFGH 


## JWT token structure

The JWT token can contain any profile fields (internal field name) as payload. These fields are automatically updated.

At least one of the listed fields should be included in the payload for unique user assignment:

- id
- email
- guid
- username


```json
{
  "iss": "example",
  "iat": "1585585174",
  "guid": "unique.user.key",
  "username": "john.doe",
  "email": "john.doe@example.com",
  "firstname": "John",
  "lastname": "Doe"
  "city": "Munich"
}
```

## Example scripts

In the directory ``humhub-path/protected/modules/jwt-sso//examples`` the JWT module also provides some example scripts for JWT token generation and SSO integration.

- **asp_ad** - SSO using VBScript and NTLM
- **php** - JWT token generation using PHP Firebase library

 