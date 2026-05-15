<?php

/**
 * @link https://www.humhub.org/
 * @copyright Copyright (c) 2019 HumHub GmbH & Co. KG
 * @license https://www.humhub.com/licences
 */

namespace humhub\modules\sso\jwt\authclient;

/**
 * Pre-1.19 marker subclass that signalled "JWT owns the user identity"
 * (via the removed `PrimaryClient` / `SyncAttributes` / `AutoSyncUsers`
 * interfaces). Since 1.19 those responsibilities live on a UserSource —
 * enable {@see \humhub\modules\sso\jwt\Module::$provideUserSource} to register
 * a {@see \humhub\modules\sso\jwt\source\JwtUserSource} that owns the user
 * lifecycle and syncs the configured attributes.
 *
 * The class is retained so that existing `authClientCollection` configs of the
 * form `'class' => JWTPrimary::class` keep working — it now behaves identically
 * to the regular {@see JWT} client.
 *
 * @deprecated since 1.2.0 — use {@see JWT} together with `provideUserSource`.
 */
class JWTPrimary extends JWT
{
}
