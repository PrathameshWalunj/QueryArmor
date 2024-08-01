# QueryArmor™: Advanced Web Application Security Tool
![Python](https://img.shields.io/badge/python-v3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Contributions welcome](https://img.shields.io/badge/contributions-welcome-orange.svg)

QueryArmor™ is an advanced security tool designed to detect and prevent SQL injection and XSS attacks in web applications. Using machine learning algorithm and pattern recognition, QueryArmor™ offers a comprehensive solution for enhancing web application security.


<img width="909" alt="Screenshot 2024-07-26 at 9 10 31 PM" src="https://github.com/user-attachments/assets/bd3ebf07-1692-47b5-9316-039dba9eee7f">

For the latest version and documentation visit our official website: [www.queryarmor.com](http://www.queryarmor.com)

## Features

* Machine learning-based detection of SQL injection and XSS vulnerabilities
* Multiple operational modes: Quick Test, Exploit Mode, and Test Mode
* Customizable payload testing against specified endpoints
* Analysis of individual queries or bulk analysis from files
* Extensible architecture allowing for custom payload addition and model retraining
* Interactive command-line interface for easy testing and integration


## How It Works

QueryArmor™ uses a multi-faceted approach to identify potential SQL injection and XSS vulnerabilities:

1. **Machine Learning Models**: Trained on extensive datasets to recognize patterns indicative of malicious queries.
2. **Exploit Mode**: Allows for comprehensive testing of endpoints using various payloads.
3. **Test Mode**: Provides detailed analysis of individual queries or files for potential vulnerabilities.
4. **Customizable Payloads**: Users can add their own payloads to enhance detection capabilities.
5. **Adaptive Learning**: Models can be retrained to adapt to new threat patterns.

## Installation

### Option 1: Direct Download
1. Visit [www.queryarmor.com](http://www.queryarmor.com) and download the latest version.
2. Extract the downloaded zip file.
3. Follow the setup instructions provided on the website.

### Option 2: GitHub Installation
1. Clone the repository: `git clone https://github.com/PrathameshWalunj/QueryArmor.git`
2. Navigate to the project directory: `cd QueryArmor`
3. Create a virtual environment: `python3 -m venv queryarmor_env`
4. Activate the virtual environment:
   - On Windows: `queryarmor_env\Scripts\activate`
   - On macOS/Linux: `source queryarmor_env/bin/activate`
5. Install the required dependencies: `pip install -r requirements.txt`

## Usage

Run the QueryArmor CLI:
python3 src/queryarmor_cli.py

### Quick Test Mode
- Test for SQL Injection: `sqli <your_query>`
- Test for XSS: `xss <your_query>`

### Exploit Mode
1. Enter exploit mode: `mode exploit`
2. Select payload type (XSS or SQLi)
3. Set target endpoint: `set_endpoint <url>`
4. Set HTTP method: `set_method <GET/POST>`
5. Set delay between requests: `set_delay <seconds>`
6. Start the test: `test`

### Test Mode
1. Enter test mode: `mode test`
2. Analyze a single query: `analyze <query>`
3. Analyze queries from a file: `analyze_file <filename>`


## Advanced Customization

- Add custom payloads to the respective .txt files
- Retrain models by running `process_payloads.py` for SQLi or `process_xss_payloads.py` for XSS
- Fine-tune models by adjusting parameters in `sql_injection_detector.py` or `xss_detector.py`

## Contributing

QueryArmor™ is open for contributions. Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

This project is licensed under the MIT License.

## Disclaimer

QueryArmor™ is a security tool designed for defensive purposes only. Always ensure you have proper authorization before using it on any systems or applications. The developers are not responsible for any misuse of this tool.

## About

QueryArmor™ is developed by Prathamesh Walunj. For more information, please contact pwalu1@unh.newhaven.edu or visit [www.queryarmor.com](http://www.queryarmor.com).
   
