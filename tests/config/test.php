<?php

/**
 * Base test configuration for the JWT-SSO module.
 *
 * 'fixtures' lists the fixture groups to load before each test run.
 * The 'default' group loads the standard HumHub fixture set (users, spaces, etc.)
 * which is required by tests that create or look up HumHub users via Registration.
 */
return [
    'fixtures' => [
        'default',
    ],
];
