# Automated Nmap Port Scanning Script

This Python script automates the process of Nmap port scanning, providing options for basic, advanced, and NSE script-based scans. It includes features such as scanning only active hosts (ignoring those that are down) and displaying a notification of how many ports will be scanned.

## Features
- **Basic scan**: Scans the top 1000 most important ports.
- **Advanced scan**: Scans all TCP and/or UDP ports (1-65535 for TCP, top 1000 for UDP).
- **NSE script scan**: Allows the user to select specific Nmap Scripting Engine (NSE) scripts to apply.
- **Active hosts only**: Displays results only for hosts that are up.
- **Port count notification**: Displays the number of ports being scanned before the scan starts.

## Installation

### Requirements
- **Python 3.x**
- **Nmap** installed on your system
- **python-nmap** library for Python

### Installing on Kali or Parrot OS

Since Kali and Parrot OS use an externally managed environment, you need to install the required Python packages in a virtual environment.

1. Create a virtual environment:
    ```bash
    python3 -m venv venv
    ```

2. Activate the virtual environment:
    ```bash
    source venv/bin/activate
    ```

3. Install the `python-nmap` package using `pip`:
    ```bash
    pip install python-nmap --break-system-packages
    ```

4. (Optional) If you need to deactivate the virtual environment:
    ```bash
    deactivate
    ```

### Running the Script

1. Ensure you have **Nmap** installed:
    ```bash
    sudo apt-get install nmap
    ```

2. Run the Python script:
    ```bash
    sudo python3 auto_nmap.py
    ```

Follow the prompts to enter the IP addresses or ranges, and select the type of scan (basic, advanced, or NSE script-based).

## Usage Example

- To scan a specific IP range, enter it like this:
    ```
    192.168.1.100-150
    ```

- For a basic scan, select "b".
- For advanced options like full port scanning or service detection, select "a".
- For NSE script scanning, select "s".

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
