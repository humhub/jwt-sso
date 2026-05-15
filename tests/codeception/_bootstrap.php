<?php

/**
 * Bootstrap for JWT-SSO module tests.
 *
 * Resolves the HumHub core root from (in order):
 *   1. `humhub_root` key in `tests/config/test.php` (env-specific override)
 *   2. `HUMHUB_TEST_CORE_ROOT` env var (handy for local dev with the module
 *      checked out outside of `protected/humhub/modules/`)
 *   3. `protected/humhub/modules/<id>/tests/codeception` layout (the module
 *      lives inside core)
 *   4. `protected/modules/<id>/tests/codeception` layout (the CI workflow
 *      from `module-coding-standards` checks out external modules here)
 */

use Codeception\Configuration;
use Codeception\Util\Autoload;

$env = $GLOBALS['env'] ?? [];

if (count($env) > 0) {
    Configuration::append(['environment' => $env]);

    $envCfgFile = dirname(__DIR__) . '/config/env/test.' . $env[0][0] . '.php';
    if (file_exists($envCfgFile)) {
        $cfg = array_merge(require_once(__DIR__ . '/../config/test.php'), require_once($envCfgFile));
    }
}

if (!isset($cfg)) {
    $cfg = require_once(__DIR__ . '/../config/test.php');
}

$bootstrapRel = '/protected/humhub/tests/codeception/_bootstrap.php';
$candidates = array_filter([
    $cfg['humhub_root'] ?? null,
    getenv('HUMHUB_TEST_CORE_ROOT') ?: null,
    dirname(__DIR__) . '/../../../../..',  // module lives at protected/humhub/modules/<id>/
    dirname(__DIR__) . '/../../../..',     // module lives at protected/modules/<id>/   (CI layout)
]);

$humhubRoot = null;
foreach ($candidates as $candidate) {
    if (file_exists($candidate . $bootstrapRel)) {
        $humhubRoot = realpath($candidate);
        break;
    }
}

if ($humhubRoot === null) {
    throw new RuntimeException(
        'JWT-SSO test bootstrap: could not locate the HumHub core. '
        . 'Set HUMHUB_TEST_CORE_ROOT or add "humhub_root" to tests/config/test.php.',
    );
}
$cfg['humhub_root'] = $humhubRoot;

// Load the shared HumHub test bootstrap
require_once($cfg['humhub_root'] . $bootstrapRel);

// Override @tests to point to this module's tests directory
Yii::setAlias('@tests', dirname(__DIR__));
Yii::setAlias('@env', '@tests/config/env');
Yii::setAlias('@root', $cfg['humhub_root']);
Yii::setAlias('@humhubTests', $cfg['humhub_root'] . '/protected/humhub/tests');

// Register the module namespace with the Yii autoloader for the dev case
// where the module checkout lives outside the core's modules directory
// (set HUMHUB_TEST_CORE_ROOT). The CI layout discovers the module via the
// regular ModuleAutoLoader, so this is a no-op then.
$moduleRoot = dirname(__DIR__, 2);
Yii::setAlias('@humhub/modules/sso/jwt', $moduleRoot);
Yii::setAlias('@jwt-sso', $moduleRoot);

Autoload::addNamespace('', Yii::getAlias('@humhubTests/codeception/_support'));
Autoload::addNamespace('tests\codeception\fixtures', Yii::getAlias('@humhubTests/codeception/fixtures'));
Autoload::addNamespace('', Yii::getAlias('@humhubTests/codeception/_pages'));
