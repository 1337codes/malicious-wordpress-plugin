# 1337Codes SQL Server Cheat Sheet

impacket-mssqlclient Administrator:user@192.168.1.13 -windows-auth

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

