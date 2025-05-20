# 1337Codes MySQL Cheat Sheet

mysql -u root -p'root' -h 192.168.148.16 -P 3306 --ssl-verify-server-cert=disabled

MySQL Server Instance  
├── Databases (Schemas)  
│ ├── Tables  
│ │ ├── Columns  
│ │ ├── Indexes  
│ │ └── Constraints  
│ ├── Views  
│ ├── Stored Procedures  
│ ├── Functions  
│ ├── Triggers  
│ └── Events  
├── Users & Privileges  
├── Information Schema (System Metadata)  
├── Performance Schema (Monitoring)  
└── Logs & Configuration

| **Task** | **MySQL Command** | **Notes** |
| --- | --- | --- |
| **Show all databases** | `SHOW DATABASES;` | Lists all databases on the MySQL server |
| **Use a database** | `USE your_database_name;` | Select a database to work with |
| **Show all tables** | `SHOW TABLES;` | Lists tables in the selected database |
| **Show table structure** | `DESCRIBE your_table_name;` | Lists columns, types, nullability, keys |
| **List columns of a table** | `SHOW COLUMNS FROM your_table_name;` | Similar to `DESCRIBE` |
| **List all users** | `SELECT User, Host FROM mysql.user;` | Users + where they can connect from |
| **Create a new user** | `CREATE USER 'username'@'host' IDENTIFIED BY 'password';` | Host can be `%` for any IP |
| **Grant privileges to a user** | `GRANT ALL PRIVILEGES ON db_name.* TO 'username'@'host';` | Use `FLUSH PRIVILEGES;` after for changes to take effect |
| **Show user privileges** | `SHOW GRANTS FOR 'username'@'host';` | Shows what permissions a user has |
| **Delete a user** | `DROP USER 'username'@'host';` |     |
| **List all databases and sizes** | Query `information_schema.SCHEMATA` and `information_schema.TABLES` | Combine to get storage info |
| **List all processes (connections)** | `SHOW PROCESSLIST;` | View running queries and sessions |
| **Kill a connection** | `KILL process_id;` | Use `Id` from `SHOW PROCESSLIST` |
| **Current database** | `SELECT DATABASE();` | Returns the name of the current DB |
| **Current user** | `SELECT CURRENT_USER();` or `SELECT USER();` | Shows connected user |
| **Show indexes on a table** | `SHOW INDEXES FROM your_table_name;` | Index name, columns, uniqueness info |
| **List foreign keys and constraints** | `SELECT * FROM information_schema.REFERENTIAL_CONSTRAINTS;` | Also check `KEY_COLUMN_USAGE` |
| **Get table size** | Query `information_schema.TABLES` | Use `DATA_LENGTH + INDEX_LENGTH` for total size |
| **Export a database** | `mysqldump -u user -p dbname > dump.sql` | Backup DB |
| **Import a database** | `mysql -u user -p dbname < dump.sql` | Restore DB |
| **Show server version** | `SELECT VERSION();` | MySQL version info |
| **Check server status** | `SHOW STATUS;` | Server statistics |
| **List functions or procedures** | `SHOW FUNCTION STATUS;` / `SHOW PROCEDURE STATUS;` | Filter by DB name for clarity |