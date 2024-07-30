import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.compose import ColumnTransformer
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import cross_val_score
import matplotlib.pyplot as plt
import re
import seaborn as sns
import joblib

class SQLInjectionDetector:
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
        def sql_keyword_count(text):
            keywords = ['SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'TABLE', 'FROM', 'WHERE']
            return sum(keyword in text.upper() for keyword in keywords)

        def special_char_ratio(text):
            special_chars = set("'\"`;,.-=")
            return sum(c in special_chars for c in text) / len(text) if text else 0

        df['sql_keyword_count'] = df['input'].apply(sql_keyword_count)
        df['special_char_ratio'] = df['input'].apply(special_char_ratio)

        word_vectorizer = TfidfVectorizer(max_features=3000, ngram_range=(1, 2))
        char_vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2, 4), max_features=2000)

        self.preprocessor = ColumnTransformer([
            ('word_tfidf', word_vectorizer, 'input'),
            ('char_tfidf', char_vectorizer, 'input'),
            ('numeric', 'passthrough', ['sql_keyword_count', 'special_char_ratio'])
        ])

        X = self.preprocessor.fit_transform(df.drop('label', axis=1))
        y = df['label']

        word_features = self.preprocessor.named_transformers_['word_tfidf'].get_feature_names_out()
        char_features = self.preprocessor.named_transformers_['char_tfidf'].get_feature_names_out()
    
        self.feature_names = (
            word_features.tolist() +
            char_features.tolist() +
            ['sql_keyword_count', 'special_char_ratio']
        )

        return X, y

    def train_model(self, X, y):
        self.model = RandomForestClassifier(n_estimators=500, max_depth=10, min_samples_split=5, random_state=42)
        self.model.fit(X, y)
        model_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models')
        os.makedirs(model_dir, exist_ok=True)
        joblib.dump(self.model, os.path.join(model_dir, 'sqli_model.joblib'))
        joblib.dump(self.preprocessor, os.path.join(model_dir, 'sqli_preprocessor.joblib'))

    def evaluate_model(self, X_test, y_test, df):

        print(f"Number of samples in test set: {len(y_test)}")
        y_pred = self.model.predict(X_test)
        print(classification_report(y_test, y_pred))
    
        cm = confusion_matrix(y_test, y_pred)
        plt.figure(figsize=(10,7))
        sns.heatmap(cm, annot=True, fmt='d')
        plt.title('Confusion Matrix')
        plt.ylabel('Actual')
        plt.xlabel('Predicted')
        plt.show()
    
     # Extracting false positives and false negatives
        false_positives = np.where((y_test == 0) & (y_pred == 1))[0]
        false_negatives = np.where((y_test == 1) & (y_pred == 0))[0]
    
        print(f"Number of False Positives: {len(false_positives)}")
        print(f"Number of False Negatives: {len(false_negatives)}")
    
        if len(false_positives) > 0:
            print("\nFalse Positives:")
            for index in false_positives:
                print(f"Input: {df.iloc[index]['input']}")
    
        if len(false_negatives) > 0:
            print("\nFalse Negatives:")
            for index in false_negatives:
                print(f"Input: {df.iloc[index]['input']}")
    def feature_importance(self):
    # Get feature importances from the model
        importances = self.model.feature_importances_

    
        if len(self.feature_names) != len(importances):
            print(f"Warning: Number of features ({len(self.feature_names)}) doesn't match number of importance scores ({len(importances)})")
        # Use the minimum length to avoid errors
            min_length = min(len(self.feature_names), len(importances))
            feature_names = self.feature_names[:min_length]
            importances = importances[:min_length]
        else:
            feature_names = self.feature_names

    # Create a DataFrame of features and their importances
        feature_imp = pd.DataFrame({'feature': feature_names, 'importance': importances})
        feature_imp = feature_imp.sort_values('importance', ascending=False)

    # Plot top 20 features
        plt.figure(figsize=(20, 10))
        sns.barplot(x="importance", y="feature", data=feature_imp.head(20))
        plt.title('Top 20 Most Important Features')
        plt.tight_layout()
        plt.show()

   
    
    def contains_sql_injection_pattern(self,input_string):
    # Convert to lowercase for case-insensitive matching
        lower_input = input_string.lower()
    
    # List of common SQL injection patterns
        patterns = [
            r'\bor\s+\d+\s*=\s*\d+',  
            r'\bunion\s+select',     
            r"'\s*or\s+'?\d+'?\s*=\s*'?\d+'?",  
            r';\s*drop\s+table',      
            r';\s*delete\s+from',                         
            r'/\*.*?\*/',             
            r'xp_cmdshell',           
            r'exec\s*\(',             
            r'union\s+all\s+select',  
            r'insert\s+into.\+values' 
            r'\b(?:admin\s*or\s*\d+\s*=\s*\d+|\'(?:admin\s*or\s*\d+\s*=\s*\d+)\')'
            r'\b(?:admin\s*or\s*\d+\s*=\s*\d+\s*--\s*)'
    ]       
    
        return any(re.search(pattern, lower_input) for pattern in patterns)


    def predict(self, input_string):
        print(f"Debug: Predicting for input: {input_string}")
        if self.contains_sql_injection_pattern(input_string):
            return "Malicious", 1.0

        df = pd.DataFrame({'input': [input_string]})
        df['sql_keyword_count'] = df['input'].apply(lambda x: sum(keyword in x.upper() for keyword in ['SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'TABLE', 'FROM', 'WHERE']))
        df['special_char_ratio'] = df['input'].apply(lambda x: sum(c in set("'\"`;,.-=") for c in x) / len(x) if x else 0)
    
        vectorized_input = self.preprocessor.transform(df)
        prediction = self.model.predict(vectorized_input)
        probability = self.model.predict_proba(vectorized_input)
        return "Malicious" if prediction[0] == 1 else "Safe", probability[0][prediction[0]]
   
    def load_model(self, model_filename='sqli_model.joblib', preprocessor_filename='sqli_preprocessor.joblib'):
        model_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models')
        print(f"Loading SQLi model from {os.path.join(model_dir, model_filename)}")
        self.model = joblib.load(os.path.join(model_dir, model_filename))
        print(f"Loading SQLi preprocessor from {os.path.join(model_dir, preprocessor_filename)}")
        self.preprocessor = joblib.load(os.path.join(model_dir, preprocessor_filename))
        
    def load_and_train_model(self):
        df = self.load_data('safe_user_inputs.txt', 'transformed_sqli_payloads.txt')
        X, y = self.preprocess_data(df)
        self.train_model(X, y)

def main():
    
    detector = SQLInjectionDetector()
    
    # Load data
    df = detector.load_data('safe_user_inputs.txt', 'transformed_sqli_payloads.txt')
    
    # Preprocess data
    X, y = detector.preprocess_data(df)
    
    # Split the data manually
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.19, random_state=42)
    
    # Train the model
    detector.train_model(X_train, y_train)
    
    # Evaluate the model
    detector.evaluate_model(X_test, y_test, df)
    
    # Show feature importance
    detector.feature_importance()

     # Test some inputs
    test_inputs = [
        "John Doe",
        "user@example.com",
        "' OR '1'='1",
        "SELECT * FROM users",
        "105.5",
        "admin",
        "string userName = ctx.getAuthenticatedUserName();",
        "root",
        "Database",
        "' OR '5'='5' /*",
        "1' and substring(@@version,2,1)=0;- -",
        "admin’ OR 1=1--; DROP TABLE users; --",
        "Benchmark",
        "BENCHMARK",
        "'OR 2=2",
        "'OR 1=1",
        "version",
        "Select",
        " GET 0x56657273696F6E, @@6461746162617365;",
        "id=984 AND IF(SUBSTRING(version(),1,1)=5,SLEEP(10),null)",
        "' UNION SELECT username, password FROM users--",
        "admin.benchmark@' AND 1=1.com",
        "Sunglasses",
        "DELAY",
        "'OR 100=100"
        
    ]

    for input_string in test_inputs:
        prediction, probability = detector.predict(input_string)
        print(f"Input: {input_string}")
        print(f"Prediction: {prediction}")
        print(f"Confidence: {probability:.2f}")
        print()

    



if __name__ == "__main__":
    main()

   