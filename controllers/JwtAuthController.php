<?php

/**
 * @link https://www.humhub.org/
 * @copyright Copyright (c) 2019 HumHub GmbH & Co. KG
 * @license https://www.humhub.com/licences
 */

namespace humhub\modules\sso\jwt\controllers;

use Yii;
use yii\web\HttpException;
use humhub\modules\user\models\User;
use humhub\modules\sso\jwt\authclient\JWT;
use humhub\modules\user\controllers\AuthController;

class JwtAuthController extends AuthController
{
    /**
     * Displays the login page for JWT authentication.
     *
     * If the user is already logged in, redirects them to the dashboard.
     * Otherwise, processes the JWT token, performs IP access check,
     * and handles authentication.
     *
     * @throws HttpException if IP access is denied.
     * @return \yii\web\Response the response object.
     */
    public function actionLogin()
    {
        // If user is already logged in, redirect to the dashboard
        if (!Yii::$app->user->isGuest) {
            return $this->goBack();
        }

        // Process JWT token
        $jwtClient = new JWT();

        // Perform IP access check
        if (!$jwtClient->checkIPAccess()) {
            throw new HttpException(403, 'Access denied.');
        }

        // Authenticate and process JWT token
        try {
            $authResult = $jwtClient->authAction($this);
        } catch (\Throwable $ex) {
            Yii::error("JWT authentication error: " . $ex->getMessage(), 'jwt-auth');
            Yii::$app->session->setFlash('error', 'JWT authentication error: ' . $ex->getMessage());
            return $this->redirect(['/user/auth/login']);
        }

        if ($authResult) {
            return $this->onAuthSuccess($jwtClient);
        }

        // Redirect to login page if authentication fails
        return $this->redirect(['/user/auth/login']);
    }

    /**
     * Handles successful authentication for JWT.
     *
     * If the user is found, logs them in. Otherwise, starts the registration process.
     *
     * @param JWT $authClient The JWT auth client.
     * @return \yii\web\Response The response object.
     */
    public function onAuthSuccess(JWT $authClient)
    {
        $user = $authClient->getUserByAttributes();

        if ($user !== null) {
            return $this->login($user, $authClient);
        }

        return $this->register($authClient);
    }

    /**
     * Registers a new user with JWT attributes.
     *
     * Checks for the required attributes (email) and attempts to create and save a new user.
     * If successful, logs the user in. Otherwise, redirects to the login page with an error message.
     *
     * @param JWT $authClient The JWT auth client.
     * @return \yii\web\Response The response object.
     */
    private function register(JWT $authClient)
    {
        $attributes = $authClient->getUserAttributes();

        if (!isset($attributes['email'])) {
            Yii::$app->session->setFlash('error', 'Email attribute is missing.');
            return $this->redirect(['/user/auth/login']);
        }

        $user = new User();
        $user->email = $attributes['email'];
        $user->username = $attributes['username'] ?? null;
        $user->status = User::STATUS_ENABLED;

        if ($user->save()) {
            $authClient->autoStoreAuthClient();
            return $this->login($user, $authClient);
        }

        Yii::$app->session->setFlash('error', 'User registration failed.');
        return $this->redirect(['/user/auth/login']);
    }

    /**
     * Logs out the user and redirects to the home page.
     *
     * @return \yii\web\Response The response object.
     */
    public function actionLogout()
    {
        Yii::$app->user->logout();
        return $this->redirect(Yii::$app->homeUrl);
    }
}
