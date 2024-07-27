# QueryArmor™

![Python](https://img.shields.io/badge/python-v3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Contributions welcome](https://img.shields.io/badge/contributions-welcome-orange.svg)

QueryArmor™ is an advanced defensive tool designed to protect web applications against SQL injection and XSS attacks. Using machine learning algorithms and pattern recognition, QueryArmor™ significantly enhances the security posture of web applications.

<img width="909" alt="Screenshot 2024-07-26 at 9 10 31 PM" src="https://github.com/user-attachments/assets/bd3ebf07-1692-47b5-9316-039dba9eee7f">

## Features
* Machine learning-based pattern recognition for identifying potentially malicious SQL and XSS payloads
* Rule-based detection for common attack patterns
* Advanced input sanitization techniques
* Adaptive learning capabilities to stay ahead of emerging threats
* Customizable rule sets for different application contexts
* Interactive command-line interface for easy testing and integration
* Comprehensive testing suite for ongoing vulnerability assessment

## How It Works

QueryArmor™ uses a unique and highly advanced approach to protect against SQL injection and XSS attacks:

1. **Custom Payload Generation**: We utilize a vast array of specialized Python functions to generate and modify a diverse set of potential attack payloads. This includes many custom functions that create variations of known attack patterns.

2. **Advanced Pattern Recognition**: Our sophisticated machine learning algorithm is trained on an extensive, custom-generated dataset. This approach allows QueryArmor™ to recognize not just known attacks, but also subtle variations and potentially new attack vectors.

3. **Rule-Based Detection**: For common and easily identifiable attack patterns, we employ a set of rules to quickly flag potential threats.

4. **Adaptive Learning**: The system can be retrained on new data, allowing it to adapt to emerging threats in the cybersecurity landscape.

5. **Intelligent Analysis**: QueryArmor™ combines insights from both its machine learning model and rule-based system to provide robust protection against known and emerging threats.

## Installation

1. Clone the repository: https://github.com/PrathameshWalunj/QueryArmor.git
2. Navigate to the project directory: cd QueryArmor
3. Install the required dependencies: pip install requirements.txt

## Usage

Run the QueryArmor CLI:
python3 src/queryarmor_cli.py

In the CLI, you can:
- Test for SQL Injection: `sqli <your_query>`
- Test for XSS: `xss <your_query>`
- View command history: `history`
- Clear the screen: `clear`
- Exit the CLI: `exit` or `quit`

## Contributing

QueryArmor™ is currently in its initial development phase. We plan to open for contributions in the future. For now, please feel free to watch this repository for updates.

## License

This project is licensed under the MIT License.

## Disclaimer

QueryArmor™ is a security tool designed for defensive purposes only. Always ensure you have proper authorization before using it on any systems or applications. The developers are not responsible for any misuse of this tool.

## About

QueryArmor™ is developed by Prathamesh Walunj. For more information, please contact pwalu1@unh.newhaven.edu.

   
