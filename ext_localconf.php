<?php
if (!defined ('TYPO3_MODE'))    die ('Access denied.');

// Register eID script
$GLOBALS['TYPO3_CONF_VARS']['FE']['eID_include']['cicSecureFiles'] = 'EXT:cicsecurefiles/lib/eidRequestResponder.php';

?>