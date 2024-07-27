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
    
    Usage Instructions:
    - To test for SQL Injection, type: sqli <your_query>
    - To test for XSS, type: xss <your_query>
    """


    prompt = 'QueryArmor> '

    def __init__(self):
        super().__init__()
        self.print_banner()
        self.xss_detector = XSSDetector()
        self.sqli_detector = SQLInjectionDetector()
        self.load_models()
        self.history = []

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
            print(f"SQLi Detector model type: {type(self.sqli_detector.model)}")
            print(f"SQLi Detector preprocessor type: {type(self.sqli_detector.preprocessor)}")
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
            print(colored("ALERT: Potential XSS attack detected!", 'red'))
        else:
            print(colored("Input appears to be safe from XSS attacks.", 'green'))

    def do_sqli(self, arg):
        """Detect SQL Injection attacks in the given input."""
        if not arg:
            print("Please provide an input string.")
            return
        result, probability = self.sqli_detector.predict(arg)
        if result == "Malicious":
            print(colored(f"ALERT: Potential SQL Injection attack detected!  (Confidence: {probability:.2f})", 'red'))
        else:
            print(colored(f"Input appears to be safe from SQL Injection attacks. (Confidence: {probability:.2f})", 'green'))

    

    def help(self):
        """Show this help message."""
        print("Available commands:")
        print("  xss <input>    Detect XSS attacks in the given input.")
        print("  sqli <input>   Detect SQL Injection attacks in the given input.")
        print("  clear           Clear the screen.")
        print("  history         List previously entered commands.")
        print("  quit            Exit the QueryArmor CLI.")
        print("  exit            Exit the QueryArmor CLI.")

    def help_xss(self):
        """Help for the xss command."""
        print("Usage: xss <input>")
        print("Description: Detects XSS attacks in the given input.")

    def help_sqli(self):
        """Help for the sqli command."""
        print("Usage: sqli <input>")
        print("Description: Detects SQL Injection attacks in the given input.")

    def help_clear(self):
        """Help for the clear command."""
        print("Usage: clear")
        print("Description: Clears the screen.")

    def help_history(self):
        """Help for the history command."""
        print("Usage: history")
        print("Description: Lists previously entered commands.")


    def precmd(self, line):
        if line.strip():  # Only add non-empty lines to history
            self.history.append(line)
        return line

    def do_history(self, arg):
        """Show command history."""
        for i, cmd in enumerate(self.history, 1):
            print(f"{i}: {cmd}")

    def do_clear(self, arg):
        '''Clear the screen.'''
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def _exit(self, arg):
        """Exit the QueryArmor CLI and clear history."""
        print("Thank you for using QueryArmor. Goodbye!")
        self.history.clear()  # Clear history on exit
        return True

    def do_exit(self, arg):
        """Handle exit command."""
        return self._exit(arg)

    def do_quit(self, arg):
        """Handle quit command."""
        return self._exit(arg)


if __name__ == '__main__':
    QueryArmorCLI().cmdloop()