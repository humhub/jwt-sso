<?php

/* @var $this \humhub\modules\ui\view\components\View */
/* @var $model \humhub\modules\sso\jwt\models\Configuration */

use yii\bootstrap\ActiveForm;
use yii\helpers\Html;
use yii\helpers\Url;

?>
<div class="container-fluid">
    <div class="panel panel-default">
        <div class="panel-heading">
            <?= Yii::t('JwtSsoModule.base', '<strong>JWT</strong> SSO configuration') ?></div>

        <div class="panel-body">
            <?php $form = ActiveForm::begin(['id' => 'configure-form', 'enableClientValidation' => false, 'enableClientScript' => false]); ?>

            <?= $form->field($model, 'url'); ?>
            <?= $form->field($model, 'sharedKey'); ?>
            <?= $form->field($model, 'supportedAlgorithms')->radioList($model->getAlgorithms(true)); ?>
            <?= $form->field($model, 'idAttribute'); ?>
            <?= $form->field($model, 'leeway'); ?>
            <?= $form->field($model, 'allowedIPs'); ?>
            <br/>

            <div class="form-group">
                <?= Html::submitButton(Yii::t('JwtSsoModule.base', 'Save'), ['class' => 'btn btn-primary', 'data-ui-loader' => '']) ?>
            </div>

            <?php ActiveForm::end(); ?>

        </div>
    </div>
</div>