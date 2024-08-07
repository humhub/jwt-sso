<?php

namespace humhub\modules\sso\jwt\controllers;

use Yii;
use humhub\modules\admin\components\Controller;
use humhub\modules\sso\jwt\models\Configuration;
use humhub\modules\sso\jwt\Module;

/**
 * Module configuation
 */
class AdminController extends Controller
{

    public function actionIndex()
    {
        $model = $this->module->getConfiguration();

        if ($model->load(Yii::$app->request->post()) && $model->save()) {
            $this->view->saved();
            return $this->redirect(['index']);
        }

        return $this->render('index', ['model' => $model]);
    }

}
