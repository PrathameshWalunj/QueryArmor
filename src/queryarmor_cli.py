import cmd
import sys
import os
import pyfiglet
from termcolor import colored
from xss_detector import XSSDetector
from sql_injection_detector import SQLInjectionDetector

class QueryArmorCLI(cmd.Cmd):
    intro = """
    Welcome to QueryArmor CLI!
    Type 'help' or '?' to list commands.
    """
    prompt = 'QueryArmor> '

    def __init__(self):
        super().__init__()
        self.print_banner()
        self.xss_detector = XSSDetector()
        self.sqli_detector = SQLInjectionDetector()
        self.load_models()

    def print_banner(self):
        banner = pyfiglet.figlet_format("QueryArmor")
        colored_banner = colored(banner, 'cyan', attrs=['bold'])
        print(colored_banner)

    
    def load_models(self):
        print("Loading pre-trained models...")
        try:
            self.xss_detector.load_model()
            self.sqli_detector.load_model()
            print("Models loaded successfully.")
        except Exception as e:
            print(f"Error loading models: {e}")
            print("Attempting to retrain SQL Injection model...")
            self.sqli_detector.load_and_train_model()
            print("SQL Injection model retrained and saved.")
        

    def do_xss(self, arg):
        """Detect XSS attacks in the given input."""
        if not arg:
            print("Please provide an input string.")
            return
        result = self.xss_detector.predict(arg)
        if result == 1:
            print("ALERT: Potential XSS attack detected!")
        else:
            print("Input appears to be safe from XSS attacks.")

    def do_sqli(self, arg):
        """Detect SQL Injection attacks in the given input."""
        if not arg:
            print("Please provide an input string.")
            return
        result = self.sqli_detector.predict(arg)
        if result == 1:
            print("ALERT: Potential SQL Injection attack detected!")
        else:
            print("Input appears to be safe from SQL Injection attacks.")

    def do_quit(self, arg):
        """Exit the QueryArmor CLI."""
        print("Thank you for using QueryArmor. Goodbye!")
        return True

    def do_exit(self, arg):
        """Exit the QueryArmor CLI."""
        return self.do_quit(arg)

if __name__ == '__main__':
    QueryArmorCLI().cmdloop()