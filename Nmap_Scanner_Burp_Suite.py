# Import necessary Burp Suite libraries
from burp import IBurpExtender, IContextMenuFactory, IContextMenuInvocation, ITab, IScanIssue
from java.awt import Component, Font, Color
from java.io import PrintWriter
from javax.swing import JMenuItem, JScrollPane, JTextArea, JPanel, JButton, JLabel, JFileChooser, JOptionPane
from threading import Thread
import subprocess
import os
import re

# BurpExtender class implements core extension functionalities
class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):
    
    # Method to initialize the extension and register components with Burp Suite
    def registerExtenderCallbacks(self, callbacks):
        # Store the callback object and helper functions
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        # Set the extension name
        self._callbacks.setExtensionName("Nmap Scanner")
        
        # Initialize output streams for logging
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        
        # Create the user interface (UI) components
        self._textarea = JTextArea()  # Text area for displaying Nmap output
        self._scroll = JScrollPane(self._textarea)  # Scroll pane for Nmap output
        
        # Create table area for displaying parsed Nmap results
        self._tablearea = JTextArea()
        self._tablescroll = JScrollPane(self._tablearea)
        self._tablearea.setEditable(False)
        self._tablearea.setFont(Font("Monospaced", Font.PLAIN, 12))  # Set a monospaced font for better formatting
        
        # Create and set up the main panel
        self._panel = JPanel()
        self._export_button = JButton("Export Nmap .nmap", actionPerformed=self.export_nmap_file)
        
        # Create and style the heading label
        self._heading = JLabel("Nmap Port Scanner")
        self._heading.setFont(Font("Arial", Font.BOLD, 16))
        self._heading.setForeground(Color(255, 128, 0))  # Set the title color to orange for better visibility
        
        # Create and style additional labels
        self._author = JLabel("Author: @TheDarkSideOps")
        self._author.setFont(Font("Arial", Font.ITALIC, 12))
        self._usage_instructions1 = JLabel("Usage:")
        self._usage_instructions1.setFont(Font("Arial", Font.BOLD, 12))  # Set "Usage:" text to bold
        self._usage_instructions2 = JLabel("1. Right-click the Domain from Sitemap and select 'Run Nmap Scan' to start scanning. OR")
        self._usage_instructions3 = JLabel("2. Right-click a request and select 'Run Nmap Scan' to start scanning")

        # Display the Nmap command that was executed
        self._nmap_command_label = JLabel("Nmap Command Executed:")
        self._nmap_command_label.setFont(Font("Arial", Font.BOLD, 12))
        self._nmap_command = JLabel("Nmap -A <Domain>")
        self._nmap_command.setFont(Font("Arial", Font.PLAIN, 12))
        
        # Set layout and positions for components
        self._panel.setLayout(None)
        self._heading.setBounds(10, 30, 500, 30)
        self._author.setBounds(10, 60, 300, 30)
        self._usage_instructions1.setBounds(10, 100, 500, 30)
        self._usage_instructions2.setBounds(10, 130, 780, 30)
        self._usage_instructions3.setBounds(10, 160, 780, 30)
        self._nmap_command_label.setBounds(10, 200, 500, 30)
        self._nmap_command.setBounds(10, 230, 500, 30)
        self._scroll.setBounds(10, 270, 780, 730)
        self._tablescroll.setBounds(800, 270, 1377, 730)
        self._export_button.setBounds(10, 1010, 200, 30)
        
        # Add components to the panel
        self._panel.add(self._heading)
        self._panel.add(self._author)
        self._panel.add(self._usage_instructions1)
        self._panel.add(self._usage_instructions2)
        self._panel.add(self._usage_instructions3)
        self._panel.add(self._nmap_command_label)
        self._panel.add(self._nmap_command)
        self._panel.add(self._scroll)
        self._panel.add(self._tablescroll)
        self._panel.add(self._export_button)
        
        # Add a custom tab to the Burp Suite UI
        callbacks.addSuiteTab(self)
        
        # Register the context menu factory
        callbacks.registerContextMenuFactory(self)
        
        # Initialize storage for unique scan results
        self.results = {}
    
    # Method to specify the tab name in Burp Suite
    def getTabCaption(self):
        return "Nmap Port Scanner"
    
    # Method to return the main panel component
    def getUiComponent(self):
        return self._panel
    
    # Method to create custom context menu items
    def createMenuItems(self, invocation):
        self._invocation = invocation
        menu_list = []
        menu_item = JMenuItem("Run Nmap Scan", actionPerformed=self.run_nmap_scan)
        menu_list.append(menu_item)
        return menu_list
    
    # Method to initiate Nmap scanning
    def run_nmap_scan(self, event):
        # Get the selected URL from the Burp context
        selected_messages = self._invocation.getSelectedMessages()
        if selected_messages:
            url = selected_messages[0].getUrl()
            hostname = url.getHost()
            self._hostname = hostname
            # Start Nmap scan in a separate thread to avoid blocking the UI
            Thread(target=self.run_nmap, args=(hostname, selected_messages)).start()
    
    # Method to run the Nmap command
    def run_nmap(self, hostname, selected_messages):
        try:
            # Update UI with scanning message
            self._textarea.setText("Running Nmap scan on: " + hostname + "\n")
            self._tablearea.setText("")  # Clear previous scan results
            nmap_output_file = "{}.nmap".format(hostname)  # Define output file name
            nmap_command = ["nmap", "-A", "-oN", nmap_output_file, hostname]  # Build Nmap command
            
            # Execute the Nmap command and capture output
            process = subprocess.Popen(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            ip_address = ""
            open_ports = []
            services = []
            protocols = []
            states = []
            versions = []
            # Parse and display Nmap output in real-time
            for line in process.stdout:
                self._textarea.append(line)
                ip_address = self.parse_nmap_output(line, hostname, open_ports, services, protocols, states, versions, ip_address)
            
            # Update the command label with the actual command executed
            self._nmap_command.setText("Nmap -A {}".format(hostname))
            
            # Wait for the Nmap process to complete
            process.wait()
            self.update_tablearea()  # Update table with parsed results
            self._textarea.append("\nNmap scan completed.")
            
            # Raise the Nmap scan results as an informational issue in Burp Suite
            self.raise_nmap_issue(selected_messages[0], hostname)
        except FileNotFoundError:
            # Handle the case where Nmap is not installed or not in the system PATH
            self._textarea.append("Error: Nmap executable not found. Please ensure Nmap is installed and available in the system PATH.")
            JOptionPane.showMessageDialog(None, "Nmap executable not found. Please ensure Nmap is installed and available in the system PATH.", "Error", JOptionPane.ERROR_MESSAGE)
        except Exception as e:
            # Handle other exceptions and display an error message
            self._textarea.append("Error: " + str(e))
            JOptionPane.showMessageDialog(None, "An error occurred: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
    
    # Method to parse Nmap output line by line
    def parse_nmap_output(self, line, hostname, open_ports, services, protocols, states, versions, ip_address):
        # Extract IP address from Nmap output
        ip_match = re.search(r"Nmap scan report for (.*) \(([\d\.]+)\)", line)
        if ip_match:
            ip_address = ip_match.group(2)
        
        # Extract details of open ports, services, and protocols
        port_match = re.search(r"(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)\s+(.+)", line)
        if port_match:
            port = port_match.group(1)
            protocol = port_match.group(2)
            state = port_match.group(3)
            service = port_match.group(4)
            version = port_match.group(5)
            # Avoid duplicate entries by using a dictionary with hostname, IP, and port as the key
            if (hostname, ip_address, port) not in self.results:
                self.results[(hostname, ip_address, port)] = {
                    "service": service,
                    "protocol": protocol,
                    "state": state,
                    "version": version
                }
            self.update_tablearea()  # Update the UI with new results
        return ip_address
    
    # Method to update the table area with scan results
    def update_tablearea(self):
        # Organize results by hostname and IP address
        formatted_results = {}
        for (hostname, ip_address, port), details in self.results.items():
            if (hostname, ip_address) not in formatted_results:
                formatted_results[(hostname, ip_address)] = {"ports": [], "details": []}
            formatted_results[(hostname, ip_address)]["ports"].append(port)
            formatted_results[(hostname, ip_address)]["details"].append(details)
        
        # Format the results into a table format
        table_text = "{:<30}\t{:<15}\t{:<10}\t{:<10}\t{:<10}\t{:<10}\t{}\n".format(
            "URL", "IP Address", "Open Ports", "Protocol", "State", "Service", "Version")
        for (hostname, ip_address), data in formatted_results.items():
            for port, detail in zip(data["ports"], data["details"]):
                table_text += "{:<30}\t{:<15}\t{:<10}\t{:<10}\t{:<10}\t{:<10}\t{}\n".format(
                    hostname, ip_address, port, detail["protocol"], detail["state"], detail["service"], detail["version"])
        
        # Display the formatted results in the table area
        self._tablearea.setText(table_text)
    
    # Method to raise Nmap results as an informational issue in Burp Suite
    def raise_nmap_issue(self, selected_message, hostname):
        # Prepare issue details
        service = selected_message.getHttpService()
        url = selected_message.getUrl()
        
        issue_name = "Nmap Port Scan Results"
        issue_detail = "The following open ports and services were identified during an Nmap scan on {}:\n\n".format(hostname)
        for (hostname, ip_address, port), details in self.results.items():
            issue_detail += (
                "Host: {}\nIP Address: {}\nPort: {}\nProtocol: {}\nState: {}\nService: {}\nVersion: {}\n\n".format(
                    hostname, ip_address, port, details["protocol"], details["state"], details["service"], details["version"]
                )
            )
        
        # Create and register a custom scan issue
        issue = CustomScanIssue(
            service,
            url,
            [selected_message],
            issue_name,
            issue_detail,
            "Information"
        )
        self._callbacks.addScanIssue(issue)  # Register the issue with Burp Suite
    
    # Method to export Nmap scan results to a .nmap file
    def export_nmap_file(self, event):
        try:
            # Open a file chooser to select the destination for the .nmap file
            chooser = JFileChooser()
            chooser.setDialogTitle("Save Nmap .nmap File")
            chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
            if chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
                dest_file = chooser.getSelectedFile().getAbsolutePath()
                # Ensure the file has a .nmap extension
                if not dest_file.lower().endswith(".nmap"):
                    dest_file += ".nmap"
                src_file = "{}.nmap".format(self._hostname)
                # Rename and move the file to the selected destination
                if os.path.exists(src_file):
                    os.rename(src_file, dest_file)
                    self._textarea.append("\nNmap output exported to: " + dest_file)
                else:
                    self._textarea.append("\nError: .nmap file not found.")
                    JOptionPane.showMessageDialog(None, ".nmap file not found.", "Error", JOptionPane.ERROR_MESSAGE)
        except Exception as e:
            # Handle errors during file export
            self._textarea.append("Error: " + str(e))
            JOptionPane.showMessageDialog(None, "An error occurred: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)

# CustomScanIssue class to define a custom scan issue for Burp Suite
class CustomScanIssue(IScanIssue):
    def __init__(self, http_service, url, http_messages, issue_name, issue_detail, severity):
        self._http_service = http_service
        self._url = url
        self._http_messages = http_messages
        self._issue_name = issue_name
        self._issue_detail = issue_detail
        self._severity = severity
    
    # Methods to provide necessary information for the issue
    def getUrl(self):
        return self._url
    
    def getHttpMessages(self):
        return self._http_messages
    
    def getHttpService(self):
        return self._http_service
    
    def getIssueName(self):
        return self._issue_name
    
    def getIssueType(self):
        return 0  # Custom issue type
    
    def getSeverity(self):
        return self._severity
    
    def getConfidence(self):
        return "Certain"  # High confidence in the results
    
    def getIssueBackground(self):
        return "This issue was automatically generated based on the results of an Nmap scan."
    
    def getRemediationBackground(self):
        return None
    
    def getIssueDetail(self):
        return self._issue_detail
    
    def getRemediationDetail(self):
        return "Investigate the exposed services and consider securing or closing unnecessary ports."
