import cmd
import sys
import os
import pyfiglet
from termcolor import colored
import time
import requests
from xss_detector import XSSDetector
from sql_injection_detector import SQLInjectionDetector

class QueryArmorCLI(cmd.Cmd):
    intro = colored("""
    Welcome to QueryArmor CLI!
    Type 'help' or '?' to list commands.
    
    WARNING: This tool is designed for security testing purposes.
    Use responsibly and only on systems you have permission to test.
    The developer is not responsible for any misuse or damage caused by this tool.

    Available modes:
    1. Quick Test (default): Use 'sqli <query>' or 'xss <query>' for quick testing
    2. Exploit Mode: Use 'mode exploit' to enter exploit mode
    3. Test Mode: Use 'mode test' to enter test mode
    """, 'yellow')

    prompt = colored('QueryArmor> ', 'cyan')

    def __init__(self):
        super().__init__()
        self.print_banner()
        self.xss_detector = XSSDetector()
        self.sqli_detector = SQLInjectionDetector()
        self.load_models()
        self.history = []
        self.mode = "quick"
        self.payloads = []
        self.results = []
        self.delay = 1  # Default delay in seconds
        self.endpoint = None
        self.method = 'GET'  # Default method
        self.payload_type = None  # 'xss' or 'sqli'
        self.project_root = self.get_project_root()


    def print_banner(self):
        banner = pyfiglet.figlet_format("QueryArmor")
        colored_banner = colored(banner, 'cyan', attrs=['bold'])
        print(colored_banner)

    def load_models(self):
        print(colored("Loading pre-trained models...", 'yellow'))
        try:
            self.xss_detector.load_model()
            self.sqli_detector.load_model()
            print(colored("Models loaded successfully.", 'green'))
        except Exception as e:
            print(colored(f"Error loading models: {e}", 'red'))


    def get_project_root(self):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.dirname(current_dir)
    
    def do_mode(self, arg):
        """Set the mode: 'exploit' or 'test'"""
        if arg.lower() not in ['exploit', 'test', 'quick']:
            print(colored("Invalid mode. Please choose 'exploit', 'test', or 'quick'.", 'red'))
            return
        self.mode = arg.lower()
        print(colored(f"Mode set to: {self.mode}", 'green'))
        if self.mode == 'exploit':
            self.select_payload_type()

    def select_payload_type(self):
        """Prompt user to select payload type and provide usage information"""
        while True:
            choice = input(colored("Select payload type (xss/sqli): ", 'yellow')).lower()
            if choice in ['xss', 'sqli']:
                self.payload_type = choice
                self.load_payloads()
                self.print_usage_info()
                break
            else:
                print(colored("Invalid choice. Please enter 'xss' or 'sqli'.", 'red'))

    def print_usage_info(self):
        """Print information on how to use the loaded payloads"""
        print(colored("\nPayload Usage Information:", 'yellow'))
        print(colored("1. Set your target endpoint:", 'cyan'))
        print(colored("   Command: set_endpoint <url>", 'cyan'))
        print(colored("   Example: set_endpoint http://example.com/vulnerable_page", 'cyan'))
    
        print(colored("\n2. Set the HTTP method (default is GET):", 'cyan'))
        print(colored("   Command: set_method <GET|POST>", 'cyan'))
        print(colored("   Example: set_method POST", 'cyan'))
    
        print(colored("\n3. Set delay between requests (default is 1 second):", 'cyan'))
        print(colored("   Command: set_delay <seconds>", 'cyan'))
        print(colored("   Example: set_delay 2", 'cyan'))
    
        print(colored("\n4. Start the test:", 'cyan'))
        print(colored("   Command: test", 'cyan'))
    
        print(colored("\nCurrent settings:", 'yellow'))
        print(colored(f"Endpoint: {self.endpoint or 'Not set'}", 'cyan'))
        print(colored(f"Method: {self.method}", 'cyan'))
        print(colored(f"Delay: {self.delay} seconds", 'cyan'))
    
    print(colored("\nUse 'help' command for more information on available commands.", 'green'))

    def load_payloads(self):
        """Load payloads based on the selected type"""
        filename = f"transformed_{self.payload_type}_payloads.txt"
        file_path = os.path.join(self.project_root, filename)
        try:
            with open(file_path, 'r') as file:
                self.payloads = [line.strip() for line in file]
            print(colored(f"Loaded {len(self.payloads)} {self.payload_type.upper()} payloads.", 'green'))
        except FileNotFoundError:
            print(colored(f"Error: {filename} not found in {self.project_root}", 'red'))
            print(colored("Please ensure the payload files are in the correct location.", 'yellow'))



    def print_exploit_info(self):
        """Print information about crafting requests in exploit mode"""
        print(colored("\nExploit Mode Information:", 'yellow'))
        print(colored("1. Set your target endpoint using 'set_endpoint <url>'", 'cyan'))
        print(colored("2. Choose HTTP method (GET/POST) using 'set_method <GET/POST>'", 'cyan'))
        print(colored("3. Set delay between requests using 'set_delay <seconds>'", 'cyan'))
        print(colored(f"Current settings:", 'yellow'))
        print(colored(f"  Endpoint: {self.endpoint or 'Not set'}", 'cyan'))
        print(colored(f"  Method: {self.method}", 'cyan'))
        print(colored(f"  Delay: {self.delay} seconds", 'cyan'))
        print(colored("Use 'test' command to start testing with these settings.", 'green'))


    def do_set_delay(self, arg):
        """Set delay between requests in seconds"""
        try:
            self.delay = float(arg)
            print(colored(f"Delay set to {self.delay} seconds.", 'green'))
        except ValueError:
            print(colored("Please provide a valid number for delay.", 'red'))

    def do_set_endpoint(self, arg):
        """Set the target endpoint for testing"""
        self.endpoint = arg
        print(colored(f"Endpoint set to: {self.endpoint}", 'green'))

    def do_set_method(self, arg):
        """Set the HTTP method for testing (GET or POST)"""
        if arg.upper() not in ['GET', 'POST']:
            print(colored("Invalid method. Please choose GET or POST.", 'red'))
            return
        self.method = arg.upper()
        print(colored(f"Method set to: {self.method}", 'green'))

    def do_test(self, arg):
        """Test payloads against the set endpoint"""
        if self.mode == 'quick':
            print(colored("Please set mode to 'exploit' or 'test' first.", 'yellow'))
            return
        if not self.payloads:
            print(colored("No payloads loaded. Please set the mode to 'exploit' and select a payload type.", 'red'))
            return
        if not self.endpoint:
            print(colored("Please set an endpoint first using 'set_endpoint <url>'.", 'red'))
            return

        print(colored(f"Testing {len(self.payloads)} {self.payload_type.upper()} payloads against {self.endpoint}", 'yellow'))
        print(colored(f"Method: {self.method}, Delay: {self.delay} seconds", 'yellow'))
        print(colored("Press Ctrl+C to stop the test at any time.", 'yellow'))

        for payload in self.payloads:
            try:
                start_time = time.time()
                if self.method == 'GET':
                    response = requests.get(f"{self.endpoint}/{payload}", timeout=5)
                else:
                    response = requests.post(self.endpoint, data=payload, timeout=5)
                end_time = time.time()

                result = {
                    'payload': payload,
                    'status_code': response.status_code,
                    'response_time': end_time - start_time,
                    'response_length': len(response.text),
                    'response_content': response.text[:2500]  
                }
                self.results.append(result)
                print(colored(f"Tested: {payload[:30]}... - Status: {response.status_code}", 'cyan'))
                print(colored("Response:", 'yellow'))
                print(colored(result['response_content'], 'white'))
                print(colored("---", 'yellow'))
                time.sleep(self.delay)
            except requests.RequestException as e:
                print(colored(f"Error testing {payload}: {str(e)}", 'red'))
            except KeyboardInterrupt:
                print(colored("\nTesting interrupted. Displaying current results.", 'yellow'))
                self.do_results(None)
                return

        print(colored("Testing completed. Use 'results' command to see full results.", 'green'))

    def do_results(self, arg):
        """Display test results"""
        if not self.results:
            print(colored("No results available. Run a test first.", 'yellow'))
            return
        for result in self.results:
            print(colored(f"Payload: {result['payload'][:50]}...", 'cyan'))
            print(colored(f"Status Code: {result['status_code']}", 'cyan'))
            print(colored(f"Response Time: {result['response_time']:.2f} seconds", 'cyan'))
            print(colored(f"Response Length: {result['response_length']}", 'cyan'))
            print(colored("Response Content:", 'yellow'))
            print(colored(result['response_content'], 'white'))
            print(colored("---", 'yellow'))

  

    def do_clear_results(self, arg):
        """Clear test results"""
        self.results = []
        print(colored("Results cleared.", 'green'))

    def do_sqli(self, arg):
        """Detect SQL Injection in the given input"""
        if not arg:
            print(colored("Please provide an input string.", 'yellow'))
            return
        result, probability = self.sqli_detector.predict(arg)
        if result == 'Malicious':
            print(colored("SQL Injection Detection: Potential SQL Injection", 'red'))
        else:
            print(colored("SQL Injection Detection: Safe", 'green'))
        print(colored(f"Confidence: {probability:.2f}", 'cyan'))

    def do_xss(self, arg):
        """Detect XSS in the given input"""
        if not arg:
            print(colored("Please provide an input string.", 'yellow'))
            return
        result = self.xss_detector.predict(arg)
        if result == 1:
            print(colored("XSS Detection: Potential XSS", 'red'))
        else:
            print(colored("XSS Detection: Safe", 'green'))

    def do_exploit(self, arg):
        """Detect XSS or SQL Injection in the given input and start testing"""
        if self.mode != 'exploit':
            print(colored("Please set mode to 'exploit' first.", 'yellow'))
            return
        if not arg:
            print(colored("Please provide an input string.", 'yellow'))
            return
        
        xss_result = self.xss_detector.predict(arg)
        sqli_result, sqli_probability = self.sqli_detector.predict(arg)
        
        if xss_result == 1:
            print(colored("Potential XSS detected.", 'red'))
            self.payload_type = 'xss'
        elif sqli_result == 'Malicious':
            print(colored(f"Potential SQL Injection detected.(Confidence: {sqli_probability:.2f})", 'red'))
            self.payload_type = 'sqli'
        else:
            print(colored("Input appears safe. No specific vulnerabilities detected.", 'green'))
            return

        self.load_payloads()

        if self.endpoint:
            self.do_test(None)
        else:
            print(colored("Please set an endpoint using 'set_endpoint <url>' before testing.", 'yellow'))

    def do_help(self, arg):
        """List available commands with "help" or detailed help with "help cmd"."""
        super().do_help(arg)
        if not arg:
            print(colored("\nAdditional Information:", 'yellow'))
            print(colored("- Use 'mode exploit' to enter exploit mode for comprehensive testing", 'cyan'))
            print(colored("- In exploit mode, set endpoint, method, and delay before testing", 'cyan'))
            print(colored("- Use 'sqli <query>' or 'xss <query>' for quick single query testing", 'cyan'))


    def do_quit(self, arg):
        """Exit the program"""
        if self.results:
            print(colored("Final Results:", 'yellow'))
            self.do_results(arg)
        print(colored("Thank you for using QueryArmor. Goodbye!", 'green'))
        return True
    

    def default(self, line):
        """Handle unknown commands"""
        print(colored(f"Unknown command: {line}", 'red'))
        print(colored("Type 'help' for a list of available commands.", 'yellow'))

if __name__ == '__main__':
    QueryArmorCLI().cmdloop()