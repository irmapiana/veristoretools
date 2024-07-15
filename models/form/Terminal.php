<?php

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

namespace app\models\form;

use Yii;
use yii\base\Model;

/**
 * Description of Terminal
 *
 * @author LENOVO
 */
class Terminal extends Model {

    const SCENARIO_VALIDATE_ADD = 'add';
    const SCENARIO_VALIDATE_COPY = 'copy';
    const SCENARIO_VALIDATE_REPORT = 'report';

    public $serialNo;
    public $deviceId;
    public $model;
    public $merchant;
    public $group;
    public $app;
    public $relocationAlert;
    public $relocationDistance;
    public $appName;
    public $appVersion;
    public $appNameReport;
    public $copySerialNo;
    public $paraList;
    public $paraListMod;
    public $paraName;
    public $paraHead;
    public $paraBody;
    public $uploadFile;
    public $uploadAllowed = false;
    public $uploadResult = false;
    public $uploadReset = false;
    public $searchType = 0;

    public function rules() {
        return [
                [['serialNo', 'model', 'merchant', 'app', 'relocationAlert'], 'required', 'on' => self::SCENARIO_VALIDATE_ADD, 'message' => 'Cannot be empty!'],
                [['copySerialNo'], 'required', 'on' => self::SCENARIO_VALIDATE_COPY, 'message' => 'Cannot be empty!'],
                [['appNameReport'], 'required', 'on' => self::SCENARIO_VALIDATE_REPORT, 'message' => 'Cannot be empty!'],
                [['merchant', 'group', 'app', 'relocationAlert', 'relocationDistance', 'searchType'], 'integer'],
                [['serialNo', 'deviceId', 'model', 'appName', 'appVersion', 'appNameReport', 'copySerialNo', 'paraList', 'paraListMod', 'paraName'], 'string'],
                [['uploadFile'], 'file', 'skipOnEmpty' => true, 'extensions' => 'xlsx, zip', 'maxSize' => Yii::$app->params['appTmsImportMaxSize']],
        ];
    }

}
