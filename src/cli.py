import argparse
import sys
import os
from xss_detector import XSSDetector
from sql_injection_detector import SQLInjectionDetector


def load_input(input_source):
    if input_source == '-':
        return sys.stdin.read().strip()
    elif os.path.isfile(input_source):
        with open(input_source, 'r') as file:
            return file.read().strip()
    else:
        return input_source.strip()

def main():
    parser = argparse.ArgumentParser(description="QueryArmor: XSS and SQL Injection detection tool")
    parser.add_argument("--mode", choices=['xss', 'sqli'], required=True, help="Detection mode: XSS or SQL Injection")
    parser.add_argument("--input", default='-', help="Input string, file path, or '-' for stdin")
    parser.add_argument("--model", help="Path to custom model file")
    
    args = parser.parse_args()

    input_text = load_input(args.input)

    if args.mode == 'xss':
        detector = XSSDetector()
    else:  # sqli
        detector = SQLInjectionDetector()

    if args.model:
        detector.load_model(args.model)
    else:
        detector.load_model()  # Load default model

    result = detector.predict(input_text)
    
    if result == 1:
        print(f"ALERT: Potential {args.mode.upper()} attack detected!")
    else:
        print(f"Input appears to be safe from {args.mode.upper()} attacks.")

if __name__ == "__main__":
    main()