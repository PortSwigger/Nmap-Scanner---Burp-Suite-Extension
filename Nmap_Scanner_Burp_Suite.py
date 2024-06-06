# Import necessary Burp Suite libraries
from burp import IBurpExtender, IContextMenuFactory, IContextMenuInvocation, ITab
from java.awt import Component, Font, Color
from java.io import PrintWriter
from javax.swing import JMenuItem, JScrollPane, JTextArea, JPanel, JButton, JLabel, JFileChooser, JOptionPane
from threading import Thread
import subprocess
import os
import re

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):
    
    def registerExtenderCallbacks(self, callbacks):
        # Set extension name
        self._callbacks = callbacks
        self._callbacks.setExtensionName("Nmap Scanner")
        
        # Initialize the standard output and error output
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        
        # Create UI components
        self._textarea = JTextArea()
        self._scroll = JScrollPane(self._textarea)
        
        # Create professional table area
        self._tablearea = JTextArea()
        self._tablescroll = JScrollPane(self._tablearea)
        self._tablearea.setEditable(False)
        self._tablearea.setFont(Font("Monospaced", Font.PLAIN, 12))
        
        self._panel = JPanel()
        self._export_button = JButton("Export Nmap XML", actionPerformed=self.export_nmap_xml)
        
        self._heading = JLabel("Nmap Port Scanner")
        self._heading.setFont(Font("Arial", Font.BOLD, 16))
        self._heading.setForeground(Color(255, 128, 0))  # Set the title color to orange
        
        self._author = JLabel("Author: @TheDarkSideOps")
        self._author.setFont(Font("Arial", Font.ITALIC, 12))
        self._usage_instructions1 = JLabel("Usage:")
        self._usage_instructions1.setFont(Font("Arial", Font.BOLD, 12))  # Set "Usage:" text to bold
        self._usage_instructions2 = JLabel("1. Right-click the Domain from Sitemap and select 'Run Nmap Scan' to start scanning. OR")
        self._usage_instructions3 = JLabel("2. Right-click a request and select 'Run Nmap Scan' to start scanning")

        self._nmap_command_label = JLabel("Nmap Command Executed:")
        self._nmap_command_label.setFont(Font("Arial", Font.BOLD, 12))
        self._nmap_command = JLabel("Nmap -A <Domain>")
        self._nmap_command.setFont(Font("Arial", Font.PLAIN, 12))
        
        # Set layout and bounds
        self._panel.setLayout(None)
        self._heading.setBounds(10, 30, 500, 30)  # Moved down to leave space above
        self._author.setBounds(10, 60, 300, 30)  # Adjusted positions accordingly
        self._usage_instructions1.setBounds(10, 100, 500, 30)
        self._usage_instructions2.setBounds(10, 130, 780, 30)
        self._usage_instructions3.setBounds(10, 160, 780, 30)
        self._nmap_command_label.setBounds(10, 200, 500, 30)
        self._nmap_command.setBounds(10, 230, 500, 30)
        self._scroll.setBounds(10, 270, 780, 730)  # Adjusted positions accordingly
        self._tablescroll.setBounds(800, 270, 1377, 730)  # Adjusted positions accordingly
        self._export_button.setBounds(10, 1010, 200, 30)  # Adjusted positions accordingly
        
        # Add components to panel
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
        
        # Add custom tab to Burp Suite
        callbacks.addSuiteTab(self)
        
        # Register context menu factory
        callbacks.registerContextMenuFactory(self)
        
        # Initialize storage for unique scan results
        self.results = {}
    
    def getTabCaption(self):
        return "Nmap Port Scanner"
    
    def getUiComponent(self):
        return self._panel
    
    def createMenuItems(self, invocation):
        self._invocation = invocation
        menu_list = []
        menu_item = JMenuItem("Run Nmap Scan", actionPerformed=self.run_nmap_scan)
        menu_list.append(menu_item)
        return menu_list
    
    def run_nmap_scan(self, event):
        # Get the selected URL
        selected_messages = self._invocation.getSelectedMessages()
        if selected_messages:
            url = selected_messages[0].getUrl()
            hostname = url.getHost()
            self._hostname = hostname
            Thread(target=self.run_nmap, args=(hostname,)).start()
    
    def run_nmap(self, hostname):
        try:
            self._textarea.setText("Running Nmap scan on: " + hostname + "\n")
            self._tablearea.setText("")
            xml_output_file = "{}.xml".format(hostname)
            nmap_command = ["nmap", "-A", "-oX", xml_output_file, hostname]
            process = subprocess.Popen(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            ip_address = ""
            open_ports = []
            services = []
            protocols = []
            states = []
            versions = []
            for line in process.stdout:
                self._textarea.append(line)
                ip_address = self.parse_nmap_output(line, hostname, open_ports, services, protocols, states, versions, ip_address)
            
            # Update the command label with the actual command
            self._nmap_command.setText("Nmap -A {}".format(hostname))
            
            process.wait()
            self.update_tablearea()
            self._textarea.append("\nNmap scan completed.")
        except FileNotFoundError:
            self._textarea.append("Error: Nmap executable not found. Please ensure Nmap is installed and available in the system PATH.")
            JOptionPane.showMessageDialog(None, "Nmap executable not found. Please ensure Nmap is installed and available in the system PATH.", "Error", JOptionPane.ERROR_MESSAGE)
        except Exception as e:
            self._textarea.append("Error: " + str(e))
            JOptionPane.showMessageDialog(None, "An error occurred: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
    
    def parse_nmap_output(self, line, hostname, open_ports, services, protocols, states, versions, ip_address):
        # Parse the Nmap output to extract useful information
        ip_match = re.search(r"Nmap scan report for (.*) \(([\d\.]+)\)", line)
        if ip_match:
            ip_address = ip_match.group(2)
        port_match = re.search(r"(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)\s+(.+)", line)
        if port_match:
            port = port_match.group(1)
            protocol = port_match.group(2)
            state = port_match.group(3)
            service = port_match.group(4)
            version = port_match.group(5)
            if (hostname, ip_address, port) not in self.results:
                self.results[(hostname, ip_address, port)] = {
                    "service": service,
                    "protocol": protocol,
                    "state": state,
                    "version": version
                }
            self.update_tablearea()
        return ip_address
    
    def update_tablearea(self):
        # Update the table area with the scan results
        formatted_results = {}
        for (hostname, ip_address, port), details in self.results.items():
            if (hostname, ip_address) not in formatted_results:
                formatted_results[(hostname, ip_address)] = {"ports": [], "details": []}
            formatted_results[(hostname, ip_address)]["ports"].append(port)
            formatted_results[(hostname, ip_address)]["details"].append(details)
        
        table_text = "{:<30}\t{:<15}\t{:<10}\t{:<10}\t{:<10}\t{:<10}\t{}\n".format(
            "URL", "IP Address", "Open Ports", "Protocol", "State", "Service", "Version")
        for (hostname, ip_address), data in formatted_results.items():
            for port, detail in zip(data["ports"], data["details"]):
                table_text += "{:<30}\t{:<15}\t{:<10}\t{:<10}\t{:<10}\t{:<10}\t{}\n".format(
                    hostname, ip_address, port, detail["protocol"], detail["state"], detail["service"], detail["version"])
        
        self._tablearea.setText(table_text)
    
    def export_nmap_xml(self, event):
        try:
            chooser = JFileChooser()
            chooser.setDialogTitle("Save Nmap XML")
            chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
            if chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
                dest_file = chooser.getSelectedFile().getAbsolutePath()
                if not dest_file.lower().endswith(".xml"):
                    dest_file += ".xml"
                src_file = "{}.xml".format(self._hostname)
                if os.path.exists(src_file):
                    os.rename(src_file, dest_file)
                    self._textarea.append("\nXML exported to: " + dest_file)
                else:
                    self._textarea.append("\nError: XML file not found.")
                    JOptionPane.showMessageDialog(None, "XML file not found.", "Error", JOptionPane.ERROR_MESSAGE)
        except Exception as e:
            self._textarea.append("Error: " + str(e))
            JOptionPane.showMessageDialog(None, "An error occurred: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
