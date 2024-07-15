<?php

namespace app\components;

use app\models\TmsLogin;
use app\models\TmsReport;
use app\models\User;
use linslin\yii2\curl\Curl;
use Yii;
use yii\db\Expression;

class TmsHelper { //NOSONAR

    const HEADER_ACCEPT = 'application/json, text/plain, */*';
    const HEADER_CONTENT_TYPE = 'application/json;charset=UTF-8';
    const HEADER_COOKIE = 'SESSION=';

    public function encrypt_decrypt($string, $encrypt = true) {
        $encrypt_method = "AES-256-CBC";
        $secret_key = '35136HH7B63C27AA74CDCC2BBRT9'; // user define private key
        $secret_iv = 'J5g275fgf5H'; // user define secret key
        $key = hash('sha256', $secret_key);
        $iv = substr(hash('sha256', $secret_iv), 0, 16); // sha256 is hash_hmac_algo
        if ($encrypt) {
            $output = openssl_encrypt($string, $encrypt_method, $key, 0, $iv);
            $output = base64_encode($output);
        } else {
            $output = openssl_decrypt(base64_decode($string), $encrypt_method, $key, 0, $iv);
        }
        return $output;
    }

    private function getSession() {
        $tmsLogin = TmsLogin::find()->where(['tms_login_enable' => '1'])->one();
        if ($tmsLogin instanceof TmsLogin) {
            return $tmsLogin->tms_login_session;
        }
        return null;
    }

    private function setSession() {
        $tmsLogin = TmsLogin::find()->where(['tms_login_enable' => '1'])->one();
        if ($tmsLogin instanceof TmsLogin) {
            $tmsLogin->tms_login_enable = '0';
            $tmsLogin->save();
        }
    }

    public function getResellerList($username) {
        $curl = new Curl();
        $response = $curl->setHeaders([
                    'Accept' => self::HEADER_ACCEPT,
                    'Content-Type' => self::HEADER_CONTENT_TYPE
                ])
                ->setRawPostData(json_encode([
                    'username' => $username
                ]))
                ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/findResellerList');
        unset($curl);
        if ($response) {
            $response = json_decode($response, true);
            if (intval($response['code']) == 0) {
                if (!empty(Yii::$app->params['appResellerList']) && is_array(Yii::$app->params['appResellerList'])) {
                    foreach ($response['data'] as $key => $value) {
                        if (!in_array($value['id'], Yii::$app->params['appResellerList'])) {
                            unset($response['data'][$key]);
                        }
                    }
                }
                return $response;
            }
        }
        return null;
    }

    public function getVerifyCode() {
        $curl = new Curl();
        $response = $curl->setHeaders([
                    'Accept' => self::HEADER_ACCEPT
                ])
                ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                ->get(Yii::$app->params['appTmsUrl'] . '/marketplace/verifycode');
        unset($curl);
        if ($response) {
            $response = json_decode($response, true);
            if (intval($response['resultCode']) == 0) {
                return $response;
            }
        }
        return null;
    }

    public function login($username, $password, $token, $code, $resellerId) {
        $cookieFile = Yii::$app->basePath . '/assets/Cookies.txt';
        if (file_exists($cookieFile)) {
            unlink($cookieFile);
        }
        $curl = new Curl();
        $response = $curl->setHeaders([
                    'Accept' => self::HEADER_ACCEPT,
                    'Content-Type' => self::HEADER_CONTENT_TYPE
                ])
                ->setRawPostData(json_encode([
                    'username' => $username,
                    'password' => $password,
                    'token' => $token,
                    'code' => $code,
                    'resellerId' => intval($resellerId)
                ]))
                ->setOption(CURLOPT_COOKIEJAR, $cookieFile)
                ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/login');
        unset($curl);
        if ($response) {
            $response = json_decode($response, true);
            if (intval($response['resultCode']) == 0) {
                if (file_exists($cookieFile)) {
                    $handle = fopen($cookieFile, "r");
                    $contents = fread($handle, filesize($cookieFile));
                    fclose($handle);
                    $response['cookies'] = trim(explode("\t", explode("#", $contents)[4])[6]);
                }
                return $response;
            } else {
                return $response;
            }
        }
        return null;
    }

    public function getDashboard() {
        $tmsSession = self::getSession();
        if (!is_null($tmsSession)) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $tmsSession
                    ])
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 5)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->get(Yii::$app->params['appTmsUrl'] . '/marketplace/dashboard');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['resultCode']) == 0) {
                    return $response;
                } else {
                    self::setSession();
                }
            }
        }
        return null;
    }

    public function getUserDashboard() {
        $retVal = [];
        $user = User::find()->where(['IS NOT', 'tms_session', new Expression('NULL')])->all();
        foreach ($user as $tmp) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $tmp->tms_session
                    ])
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 5)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->get(Yii::$app->params['appTmsUrl'] . '/marketplace/dashboard');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['resultCode']) == 0) {
                    $retVal[$tmp->user_name] = true;
                } else {
                    $tmp->tms_session = null;
                    $tmp->save();
                    $retVal[$tmp->user_name] = false;
                }
            }
        }
        return $retVal;
    }
    
    public function getTerminalListToFile() {
        $process = false;
        $terminalFile = Yii::$app->basePath . '/assets/Terminals.txt';
        $totalAllList = 0;
        $selectAllList = [];
        $saTotalPage = 1;
        for ($saPageIdx=1;$saPageIdx<=$saTotalPage;$saPageIdx+=1) {
            $response = self::getTerminalList(null, $saPageIdx);
            if (!is_null($response)) {
                $process = true;
                $saTotalPage = intval($response['totalPage']);
                $tmpList = '';
                foreach ($response['terminalList'] as $saTerminal) {
                    $totalAllList += 1;
                    $tmpList .= ($saTerminal['sn'] . '|');
                }
                $selectAllList[$saPageIdx-1] = substr($tmpList, 0, -1);
            } else {
                break;
            }
            if (($saPageIdx % 15) == 0) {
                self::getUserDashboard();
            }
        }
        if ($process) {
            $handle = fopen($terminalFile, "w");
            if (flock($handle, LOCK_EX)) {
                fwrite($handle, $totalAllList . "\n");
                fwrite($handle, json_encode($selectAllList) . "\n");
                flock($handle, LOCK_UN);
            }
            fclose($handle);
        }
    }

    public function getTerminalDetail($serialNum, $session = null, $rcCheck = true) {
        if (is_null($session)) {
            $tmsSession = self::getSession();
        } else {
            $tmsSession = $session;
        }
        if (!is_null($tmsSession)) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $tmsSession
                    ])
                    ->setRawPostData(json_encode([
                        'sn' => $serialNum,
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/terminal/detail');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if ($rcCheck) {
                    if (intval($response['resultCode']) == 0) {
                        return $response;
                    }
                } else {
                    return $response;
                }
            }
        }
        return null;
    }

    public function getTerminalParameter($serialNum, $appId, $session = null, $rcCheck = true) {
        if (is_null($session)) {
            $tmsSession = self::getSession();
        } else {
            $tmsSession = $session;
        }
        if (!is_null($tmsSession)) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $tmsSession
                    ])
                    ->setRawPostData(json_encode([
                        'sn' => $serialNum,
                        'appId' => intval($appId),
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/terminal/app/parameter/list');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if ($rcCheck) {
                    if (intval($response['resultCode']) == 0) {
                        return $response;
                    }
                } else {
                    return $response;
                }
            }
        }
        return null;
    }

    public function updateDeviceId($serialNum, $model, $merchantId, $groupList, $deviceId, $session = null, $rcCheck = true) {
        if (is_null($session)) {
            $tmsSession = self::getSession();
        } else {
            $tmsSession = $session;
        }
        if (!is_null($tmsSession)) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $tmsSession
                    ])
                    ->setRawPostData(json_encode([
                        'sn' => $serialNum,
                        'model' => $model,
                        'merchantId' => intval($merchantId),
                        'groupList' => $groupList,
                        'deviceId' => $deviceId,
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/terminal/app/config/save');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if ($rcCheck) {
                    if (intval($response['resultCode']) == 0) {
                        return $response;
                    }
                } else {
                    return $response;
                }
            }
        }
        return null;
    }

    public function getTerminalList($session, $pageNum) {
        if (is_null($session)) {
            $tmsSession = self::getSession();
        } else {
            $tmsSession = $session;
        }
        if (!is_null($tmsSession)) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $tmsSession
                    ])
                    ->setRawPostData(json_encode([
                        'pageNum' => intval($pageNum),
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/terminal/page');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['resultCode']) == 0) {
                    return $response;
                }
            }
        }
        return null;
    }

    public function getTerminalListSearch($session, $pageNum, $search, $queryType = 0) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $session
                    ])
                    ->setRawPostData(json_encode([
                        'pageNum' => intval($pageNum),
                        'queryInfo' => $search,
                        'queryType' => intval($queryType)
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/terminal/search');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['resultCode']) == 0) {
                    return $response;
                }
            }
        }
        return null;
    }

    public function copyTerminal($sourceSn, $destSn, $session = null, $rcCheck = true) {
        if (is_null($session)) {
            $tmsSession = self::getSession();
        } else {
            $tmsSession = $session;
        }
        if (!is_null($tmsSession)) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $tmsSession
                    ])
                    ->setRawPostData(json_encode([
                        'destSn' => $destSn,
                        'sourceSn' => $sourceSn,
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/terminal/copy');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if ($rcCheck) {
                    $rc = intval($response['resultCode']);
                    if (($rc == 0) || ($rc == 1)) {
                        return $response;
                    }
                } else {
                    return $response;
                }
            }
        }
        return null;
    }

    public function deleteTerminal($sn, $session = null) {
        if (is_null($session)) {
            $tmsSession = self::getSession();
        } else {
            $tmsSession = $session;
        }
        if (!is_null($tmsSession)) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $tmsSession
                    ])
                    ->setRawPostData(json_encode([
                        'sn' => $sn,
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/terminal/delete');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['resultCode']) == 0) {
                    return $response;
                }
            }
        }
        return null;
    }

    public function getMerchantList($session) {
        if (is_null($session)) {
            $tmsSession = self::getSession();
        } else {
            $tmsSession = $session;
        }
        if (!is_null($tmsSession)) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $tmsSession
                    ])
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/common/query/merchant');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['resultCode']) == 0) {
                    return $response;
                }
            }
        }
        return null;
    }

    public function getGroupList($session) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $session
                    ])
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/common/query/group');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['resultCode']) == 0) {
                    return $response;
                }
            }
        }
        return null;
    }

    public function getAppList($session) {
        if (is_null($session)) {
            $tmsSession = self::getSession();
        } else {
            $tmsSession = $session;
        }
        if (!is_null($tmsSession)) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $tmsSession
                    ])
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/app/hasTemplate');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['resultCode']) == 0) {
                    return $response;
                }
            }
        }
        return null;
    }

    public function addTerminal($session, $sn, $model, $merchantId, $groupList, $deviceId, $moveConf, $distance, $rcCheck = true) {
        if (is_null($session)) {
            $tmsSession = self::getSession();
        } else {
            $tmsSession = $session;
        }
        if (!is_null($tmsSession)) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $tmsSession
                    ])
                    ->setRawPostData(json_encode([
                        'sn' => $sn,
                        'model' => $model,
                        'merchantId' => intval($merchantId),
                        'groupList' => $groupList ? $groupList : [],
                        'deviceId' => $deviceId,
                        'moveConf' => intval($moveConf),
                        'distance' => $distance
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/terminal/add');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if ($rcCheck) {
                    if (intval($response['resultCode']) == 0) {
                        return $response;
                    }
                } else {
                    if (isset($response['desc'])) {
                        $response['desc'] = str_replace('SN', 'CSI', $response['desc']);
                    }
                    return $response;
                }
            }
        }
        return null;
    }

    public function addParameter($session, $sn, $model, $merchantId, $groupList, $deviceId, $moveConf, $distance, $appId, $rcCheck = true) {
        if (is_null($session)) {
            $tmsSession = self::getSession();
        } else {
            $tmsSession = $session;
        }
        if (!is_null($tmsSession)) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $tmsSession
                    ])
                    ->setRawPostData(json_encode([
                        'sn' => $sn,
                        'paraList' => [],
                        'model' => $model,
                        'merchantId' => intval($merchantId),
                        'groupList' => $groupList ? $groupList : [],
                        'deviceId' => $deviceId,
                        'moveConf' => intval($moveConf),
                        'dataList' => [],
                        'operationTerminalApps' => [
                            0 => [
                                'appId' => intval($appId),
                                'operationType' => 1
                            ]
                        ],
                        'distance' => $distance,
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/terminal/app/param/save');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if ($rcCheck) {
                    if (intval($response['resultCode']) == 0) {
                        return $response;
                    }
                } else {
                    return $response;
                }
            }
        }
        return null;
    }

    public function updateParameter($sn, $paraList, $model, $merchantId, $groupList, $deviceId, $moveConf, $distance, $appId, $session = null, $rcCheck = true) {
        if (is_null($session)) {
            $tmsSession = self::getSession();
        } else {
            $tmsSession = $session;
        }
        if (!is_null($tmsSession)) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $tmsSession
                    ])
                    ->setRawPostData(json_encode([
                        'sn' => $sn,
                        'paraList' => $paraList,
                        'model' => $model,
                        'merchantId' => intval($merchantId),
                        'groupList' => $groupList,
                        'deviceId' => $deviceId,
                        'moveConf' => intval($moveConf),
                        'dataList' => [
                            0 => [
                                'appId' => intval($appId),
                                'parameterInfoList' => $paraList
                            ]
                        ],
                        'operationTerminalApps' => [],
                        'distance' => $distance,
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/terminal/app/param/save');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if ($rcCheck) {
                    if (intval($response['resultCode']) == 0) {
                        return $response;
                    }
                } else {
                    return $response;
                }
            }
        }
        return null;
    }

    public function getAppListSearch($session, $name) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $session
                    ])
                    ->setRawPostData(json_encode([
                        'name' => $name,
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/report/searchAppList');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['code']) == 0) {
                    return $response;
                }
            }
        }
        return null;
    }

    public function getMerchantManageList($session, $pageNum) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $session
                    ])
                    ->setRawPostData(json_encode([
                        'pageNum' => intval($pageNum),
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/merchant/page');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['resultCode']) == 0) {
                    return $response;
                }
            }
        }
        return null;
    }

    public function getMerchantManageListSearch($session, $pageNum, $search) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $session
                    ])
                    ->setRawPostData(json_encode([
                        'pageNum' => intval($pageNum),
                        'queryInfo' => $search,
                        'queryType' => 0
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/merchant/search');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['resultCode']) == 0) {
                    return $response;
                }
            }
        }
        return null;
    }

    public function deleteMerchantManage($session, $merchantId) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $session
                    ])
                    ->setRawPostData(json_encode([
                        'id' => $merchantId,
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/merchant/delete');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['resultCode']) == 0) {
                    return $response;
                }
            }
        }
        return null;
    }

    public function addMerchantManage($merchantName, $companyName, $address, $postCode, $typeId, $contactFirstName, $contactLastName, $email, $mobilePhone, $telePhone, $countryId, $stateId, $cityId, $districtId, $session = null, $rcCheck = true) {
        if (is_null($session)) {
            $tmsSession = self::getSession();
        } else {
            $tmsSession = $session;
        }
        if (!is_null($tmsSession)) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $tmsSession
                    ])
                    ->setRawPostData(json_encode([
                        'merchantName' => $merchantName,
                        'companyName' => $companyName,
                        'address' => $address,
                        'postCode' => $postCode ? $postCode : "",
                        'typeId' => intval($typeId),
                        'contactFirstName' => $contactFirstName,
                        'contactLastName' => $contactLastName,
                        'email' => $email,
                        'mobilePhone' => $mobilePhone,
                        'telePhone' => $telePhone ? $telePhone : "",
                        'countryId' => intval($countryId),
                        'stateId' => intval($stateId),
                        'cityId' => intval($cityId),
                        'districtId' => intval($districtId)
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/merchant/add');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if ($rcCheck) {
                    if (intval($response['resultCode']) == 0) {
                        return $response;
                    }
                } else {
                    return $response;
                }
            }
        }
        return null;
    }

    public function editMerchantManage($session, $id, $merchantName, $companyName, $address, $postCode, $typeId, $contactFirstName, $contactLastName, $email, $mobilePhone, $telePhone, $countryId, $stateId, $cityId, $districtId, $rcCheck = true) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $session
                    ])
                    ->setRawPostData(json_encode([
                        'id' => intval($id),
                        'merchantName' => $merchantName,
                        'companyName' => $companyName,
                        'address' => $address,
                        'postCode' => $postCode ? $postCode : "",
                        'typeId' => intval($typeId),
                        'contactFirstName' => $contactFirstName,
                        'contactLastName' => $contactLastName,
                        'email' => $email,
                        'mobilePhone' => $mobilePhone,
                        'telePhone' => $telePhone ? $telePhone : "",
                        'countryId' => intval($countryId),
                        'stateId' => intval($stateId),
                        'cityId' => intval($cityId),
                        'districtId' => intval($districtId)
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/merchant/edit');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if ($rcCheck) {
                    if (intval($response['resultCode']) == 0) {
                        return $response;
                    }
                } else {
                    return $response;
                }
            }
        }
        return null;
    }

    public function getCountryList($session) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $session
                    ])
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/common/query/country');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['resultCode']) == 0) {
                    return $response;
                }
            }
        }
        return null;
    }

    public function getStateList($session, $countryId) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $session
                    ])
                    ->setRawPostData(json_encode([
                        'countryId' => intval($countryId),
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/common/query/state');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['resultCode']) == 0) {
                    return $response;
                }
            }
        }
        return null;
    }

    public function getCityList($session, $stateId) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $session
                    ])
                    ->setRawPostData(json_encode([
                        'stateId' => intval($stateId),
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/common/query/city');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['resultCode']) == 0) {
                    return $response;
                }
            }
        }
        return null;
    }

    public function getDistrictList($cityId, $session = null, $rcCheck = true) {
        if (is_null($session)) {
            $tmsSession = self::getSession();
        } else {
            $tmsSession = $session;
        }
        if (!is_null($tmsSession)) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $tmsSession
                    ])
                    ->setRawPostData(json_encode([
                        'cityId' => intval($cityId),
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/common/query/district');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if ($rcCheck) {
                    if (intval($response['resultCode']) == 0) {
                        return $response;
                    }
                } else {
                    return $response;
                }
            }
        }
        return null;
    }

    public function getBusinessList($session) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $session
                    ])
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/common/query/business');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['resultCode']) == 0) {
                    return $response;
                }
            }
        }
        return null;
    }
    
    public function getMerchantManageDetail($merchantId, $session = null, $rcCheck = true) {
        if (is_null($session)) {
            $tmsSession = self::getSession();
        } else {
            $tmsSession = $session;
        }
        if (!is_null($tmsSession)) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $tmsSession
                    ])
                    ->setRawPostData(json_encode([
                        'id' => $merchantId,
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/merchant/detail');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if ($rcCheck) {
                    if (intval($response['resultCode']) == 0) {
                        return $response;
                    }
                } else {
                    return $response;
                }
            }
        }
        return null;
    }
    
    public function getGroupManageList($session, $pageNum) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $session
                    ])
                    ->setRawPostData(json_encode([
                        'pageNum' => intval($pageNum),
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/group/page');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['resultCode']) == 0) {
                    return $response;
                }
            }
        }
        return null;
    }

    public function getGroupManageListSearch($session, $pageNum, $search) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $session
                    ])
                    ->setRawPostData(json_encode([
                        'pageNum' => intval($pageNum),
                        'queryInfo' => $search
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/group/search');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['resultCode']) == 0) {
                    return $response;
                }
            }
        }
        return null;
    }

    public function deleteGrouptManage($session, $groupId) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $session
                    ])
                    ->setRawPostData(json_encode([
                        'id' => $groupId,
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/group/delete');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['resultCode']) == 0) {
                    return $response;
                }
            }
        }
        return null;
    }

    public function getGroupManageTerminal($session, $groupId, $rcCheck = true) {
        if (is_null($session)) {
            $tmsSession = self::getSession();
        } else {
            $tmsSession = $session;
        }
        if (!is_null($tmsSession)) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $tmsSession
                    ])
                    ->setRawPostData(json_encode([
                        'groupId' => $groupId,
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/groupTerminal/all');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if ($rcCheck) {
                    if (intval($response['code']) == 0) {
                        return $response;
                    }
                } else {
                    return $response;
                }
            }
        }
        return null;
    }

    public function getGroupTerminalSearch($session, $search) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $session
                    ])
                    ->setRawPostData(json_encode([
                        'cityId' => "",
                        'countryId' => "",
                        'districtId' => "",
                        'queryInfo' => $search,
                        'queryType' => 0,
                        'stateId' => ""
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/group/terminal/search');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (intval($response['resultCode']) == 0) {
                    return $response;
                }
            }
        }
        return null;
    }

    public function addGroupManage($session, $groupName, $terminalList, $rcCheck = true) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $session
                    ])
                    ->setRawPostData(json_encode([
                        'groupName' => $groupName,
                        'terminalIds' => $terminalList
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/group/add');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if ($rcCheck) {
                    if (intval($response['resultCode']) == 0) {
                        return $response;
                    }
                } else {
                    return $response;
                }
            }
        }
        return null;
    }
    
    public function editGroupManage($session, $groupId, $groupName, $groupTerminals, $rcCheck = true) {
        if ($session) {
            $curl = new Curl();
            $response = $curl->setHeaders([
                        'Accept' => self::HEADER_ACCEPT,
                        'Content-Type' => self::HEADER_CONTENT_TYPE,
                        'Cookie' => self::HEADER_COOKIE . $session
                    ])
                    ->setRawPostData(json_encode([
                        'groupId' => $groupId,
                        'groupName' => $groupName,
                        'groupTerminals' => $groupTerminals
                    ]))
                    ->setOption(CURLOPT_CONNECTTIMEOUT, 30)
                    ->setOption(CURLOPT_SSL_VERIFYPEER, false)
                    ->post(Yii::$app->params['appTmsUrl'] . '/marketplace/group/edit');
            unset($curl);
            if ($response) {
                $response = json_decode($response, true);
                if (isset($response['code'])) {
                    $response['resultCode'] = $response['code'];
                }
                if ($rcCheck) {
                    if (intval($response['code']) == 0) {
                        return $response;
                    }
                } else {
                    return $response;
                }
            }
        }
        return null;
    }
    
}
