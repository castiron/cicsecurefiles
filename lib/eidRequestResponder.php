<?php

require_once(PATH_tslib.'class.tslib_eidtools.php');

class secureDownloader {
	function __construct() {
		$selected = intval($selected);
		$feUserObj = tslib_eidtools::initFeUser();
		$this->feUserObj = $feUserObj;

	
		// set the path
		$this->requestPath = t3lib_div::getIndpEnv('REQUEST_URI');
		if($this->requestPath == false) return $this->error('NOREQUESTPATH');



		// Copied from index_ts.php (with minor changes)
		// the value this->formfield_status is set to empty in order to disable login-attempts to the backend account through this script
		$this->BE_USER = t3lib_div::makeInstance('t3lib_tsfeBeUserAuth');	// New backend user object
		$this->BE_USER->OS = TYPO3_OS;
		$this->BE_USER->lockIP = $TYPO3_CONF_VARS['BE']['lockIP'];
		$this->BE_USER->start();			// Object is initialized
		$this->BE_USER->unpack_uc('');
		if ($this->BE_USER->user['uid'])	{
			$this->BE_USER->fetchGroupData();
		}
			// Unset the user initialization.
		if (!$this->BE_USER->checkLockToIP() || !$this->BE_USER->checkBackendAccessSettingsFromInitPhp() || !$this->BE_USER->user['uid']) {
			$this->BE_USER = NULL;
		}
		// /Copied from index_ts.php

		// if no user, no product may be downloads -- TURN BACK ON!
		if(!$feUserObj->user['uid'] && !$this->BE_USER->user['uid']) return $this->error('PERM');
		$feuserUid = $feUserObj->user['uid'];

		// validate path
		// strip leading slash
		if(strpos($this->requestPath,'/') === 0) $this->requestPath = substr($this->requestPath,1);

			
		// check for valid
		if(t3lib_div::validPathStr($this->requestPath) == false) return $this->error('INVALIDPATH');
		if(t3lib_div::validPathStr(urldecode($this->requestPath)) == false) return $this->error('INVALIDPATH');

		$allowed = false;

		$securityType = (string) t3lib_div::_GET('securityType');

		$params = t3lib_div::_GET();
		unset($params['eID']);
		unset($params['securityType']);

		if($securityType) {
			if($this->checkAccess($securityType,$this->requestPath,$params)) {
				$allowed = true;
			}
		} else {
			$this->error('NOSECURITYTYPESPECIFIED');
		}

		if($allowed == true) $this->deliverFile();

		// if we still haven't delivered the file, we go to error.
		return $this->error('PERM');
	}

	function checkAccess($securityType, $requestPath,$params = array()) {
		// If the user is logged into the backend, allow access. This could be made more granular
		// and robust, but we don't need any more than this at this point
		if($this->BE_USER->user['uid']) {
			$access = true;
		} else {
			$methodName = 'checkAccess_'.(string) $securityType;
			$access = false;
			if(method_exists($this,$methodName)) {
				if($this->$methodName((string) $requestPath,$params)) {
					$access = true;
				}
			}
		}
		return $access;
	}
	
	function checkAccess_groupFolderFromUidArg($requestPath,$params = array()) {
		if(is_array($params['uid'])) {
			foreach($params['uid'] as $uid) {
				$groupUid = (int) $uid;
				if($groupUid) {
					if(t3lib_div::inList($this->feUserObj->user['usergroup'],$groupUid)) {
						return true;
					}
				}
			}
		} else {
			$groupUid = (int) $params['uid'];
			if($groupUid) {
				if(t3lib_div::inList($this->feUserObj->user['usergroup'],$groupUid)) {
					return true;
				}
			}
		}
		return false;
	}
	
	
	/**
	 * We expect the folder name that the file is in to be user_### where ### is the uid of the logged in user, otherwise, no access
	 *
	 */
	function checkAccess_userFolderByUid($requestPath,$params = array()) {
		$userFolderName = 'user_'.$this->feUserObj->user['uid'];
		$pathInfo = pathinfo($requestPath);
		$requestPathArr = split('/',$pathInfo['dirname']);

		$compareDirName = end($requestPathArr);

		if($userFolderName == $compareDirName) {
			return true;
		}

		return false;
	}
	
	/**
	 * We expect the folder name that the file is in to be user_### where ### is the username of the logged in user, otherwise, no access
	 *
	 */
	function checkAccess_userFolderByUsername($requestPath,$params = array()) {
		$userFolderName = 'user_'.$this->feUserObj->user['username'];
		$pathInfo = pathinfo($requestPath);
		$requestPathArr = split('/',$pathInfo['dirname']);

		$compareDirName = end($requestPathArr);

		if($userFolderName == $compareDirName) {
			return true;
		}

		return false;
	}

	
	/**
	 * We need to look at the folder name and see if group_### has a value ### that is in the list of group uids to which this group belongs
	 *
	 */
	function checkAccess_groupFolderByUid($requestPath,$params = array()) {
		$pathInfo = pathinfo($requestPath);
		$requestPathArr = split('/',$pathInfo['dirname']);
		$compareDirName = end($requestPathArr);

		if(preg_match('/^group_([0-9]+)$/',$compareDirName,$matches)) {
			$groupUid = $matches[1];
			
			if(t3lib_div::inList($this->feUserObj->user['usergroup'],$groupUid)) {
				return true;
			}
		}
		return false;
	}

	function checkAccessByGroup($groups) {
		$this->feUserObj->fetchGroupData();
		// validate groups
		$groups = explode(',',$groups);
		$groupsArr =  array();
		foreach($groups as $group) {
			$group = intval($group);
			if($group) $groupsArr[] = $group;
		}
		
		if(is_array($this->feUserObj->groupData['uid'])) {
			// check access
			foreach($groupsArr as $group) {
				if(in_array($group,$this->feUserObj->groupData['uid'])) return true;
			}
		}
		return false;
	}


	function deliverFile() {
		// check if file exists
		$absPath = t3lib_div::getFileAbsFileName($this->requestPath);
		if(t3lib_div::isAllowedAbsPath($absPath) == false) return $this->error('INVALIDPATH-3');

		if(!@file_exists($absPath)) return $this->error('NOTFOUND');

		$info = pathinfo($absPath);

		switch($info['extension']) {
			case 'pdf': $ctype='application/pdf'; break;
			case 'exe': $ctype='application/octet-stream'; break;
			case 'zip': $ctype='application/zip'; break;
			case 'doc': $ctype='application/msword'; break;
			case 'xls': $ctype='application/vnd.ms-excel'; break;
			case 'ppt': $ctype='application/vnd.ms-powerpoint'; break;
			case 'gif': $ctype='image/gif'; break;
			case 'png': $ctype='image/png'; break;
			case 'jpeg':
			case 'jpg': $ctype='image/jpg'; break;
			case 'mp3': $ctype='audio/mpeg'; break;
			case 'wav': $ctype='audio/x-wav'; break;
			case 'mpeg':
			case 'mpg':
			case 'mpe': $ctype='video/mpeg'; break;
			case 'mov': $ctype='video/quicktime'; break;
			case 'avi': $ctype='video/x-msvideo'; break;
			case 'htm':
			case 'html': $ctype='text/html'; break;
			case 'txt': $ctype = 'text/plain'; break;
			case 'conf':
			case 'config':
			case 'php':
				 $this->throw404(); break;
			default: $ctype='application/force-download';
		}

		// deliver the file.
		header('Pragma: public');
	    header('Expires: 0');
	    header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
	    header('Cache-Control: public');
	    header('Content-Description: File Transfer');
	    header('Content-length: '.filesize($absPath));
	    header('Content-disposition: attachment; filename="'.basename($absPath).'"');
		header('Content-Transfer-Encoding: binary');
	    header('Content-type: "'.$ctype.'"');

	    readfile($absPath);
		die();
	}

	function error($type) {
		$this->throw404();
	}
	
	function throw404() {
		$tsfe = t3lib_div::makeInstance('tslib_fe', $GLOBALS['TYPO3_CONF_VARS'], 0, 0);
		$tsfe->pageNotFoundAndExit();
	}
}

$sdl = new secureDownloader;

?>
