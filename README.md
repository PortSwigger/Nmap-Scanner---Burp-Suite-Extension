# Nmap Scanner - Burp Suite Extension

The Nmap Scanner Burp Suite Extension integrates Nmap's powerful network scanning capabilities directly into the Burp Suite interface. This extension provides an easy-to-use graphical interface for initiating and viewing the results of Nmap scans within Burp Suite, making it an essential tool for security professionals and penetration testers.

## Features

- **Seamless Integration**: Adds a custom tab within Burp Suite for easy access.
- **Context Menu Option**: Right-click any domain or request in Burp Suite to initiate an Nmap scan.
- **Real-time Output**: Displays Nmap scan output in real-time within Burp Suite.
- **Detailed Results**: Parses and formats scan results, displaying them in a professional, readable format.
- **XML Export**: Option to export Nmap scan results as an XML file.

## Installation

1. Ensure that Burp Suite and Nmap are installed on your system.
2. Place the Python script in the appropriate extensions directory for Burp Suite.
3. Load the extension within Burp Suite by navigating to `Extender -> Extensions` and selecting the script.

## Usage

### Run Nmap Scan
- Right-click a domain from the Sitemap or a specific request and select "Run Nmap Scan" to start scanning.

![image](https://github.com/TheDarkSideOps/Nmap-Scanner---Burp-Suite-Extension/assets/128429716/f4c58cea-cc85-4b5d-93b4-f6a2d87da087)

OR

![image](https://github.com/TheDarkSideOps/Nmap-Scanner---Burp-Suite-Extension/assets/128429716/409a2111-3908-4611-8a78-b04eac345c8a)


### View Results
- The scan results, including open ports, services, protocols, states, and versions, are displayed in a formatted table.

![image](https://github.com/TheDarkSideOps/Nmap-Scanner---Burp-Suite-Extension/assets/128429716/bc6902ab-101e-49ec-9399-0ffdc9984747)


### Export Results
- Click the "Export Nmap XML" button to save the scan results as an XML file.

## UI Components

**Nmap Port Scanner Tab**: Custom tab added to Burp Suite with the following components:

- **Heading**: "Nmap Port Scanner" with styled text.
- **Author**: "Author: Parth Patel (@TheDarkSideOps)".
- **Usage Instructions**: Detailed usage instructions displayed in a readable format.
- **Nmap Command**: Displays the executed Nmap command.
- **Output Area**: Real-time display of Nmap scan output.
- **Results Table**: Formatted table showing scan results.
- **Export Button**: Button to export scan results as an XML file.

## License

This project is licensed under the MIT License.
