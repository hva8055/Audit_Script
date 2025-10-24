
# CIS Benchmark Audit Tool

This is a graphical user interface (GUI) application designed to automate CIS (Center for Internet Security) benchmark audits for multiple operating systems. It provides a central dashboard to run compliance scripts and view their output.

## Features

* **Graphical Dashboard:** A simple GUI built with PyQt5 to run audits.
* **Cross-Platform:** Designed to run audits for both Windows and Ubuntu.
* **Multiple Audit Levels:** For Ubuntu, supports running CIS Level 1, Level 2, and a combined Level 3 (L1+L2) audit.
* **Output Capture:** Displays the live console output from the audit scripts directly in the application.
* **CSV Reporting:** The Ubuntu audit scripts generate detailed `.csv` reports (e.g., `audit_report_level1.csv`) in the project directory.

## Project Structure
```bash
/CIS-Audit-Tool/
├── main.py               
├── requirements.txt      
├── README.md            
├── .gitignore            
├── Ubuntu/               
│   ├── level1.sh  
│   ├── level2.sh  
│   └── level3.sh   
├── Windows/              
│   └── windows_audit_l1.ps1    
│   └── windows_auditl2.ps1   
│   └── windows_auditl3.ps1  
└── venv/                 
```



## Prerequisites (System Libraries)

Before setting up the Python environment, you may need to install some system-level libraries.

**For Ubuntu (Debian-based):**
(This is where you list libraries like the one from your error!)

sudo apt update
sudo apt install python3-venv libxcb-xinerama0

## Setup & Installation for Ubuntu

This project must be run inside a Python virtual environment.

1.  **Clone the project:**
```bash
    git clone https://github.com/hva8055/Audit_Script
```
```bash    
    cd Audit_Script
```
2.  **Create a virtual environment:**
```bash
    python3 -m venv venv
```
3.  **Activate the virtual environment:**
```bash
    source venv/bin/activate
```
    *(You will see (venv) at the start of your terminal prompt)*

4.  **Install all required Python libraries:**
 ```bash   
    pip install -r requirements.txt 
```

5.  **Run the script:**
```bash
    python main.py
```
6 **Enter the root Password After you have runned the Python script**

## Setup & Installation for Windows

This project must be run inside a Python virtual environment.

1.  **Clone the project:**
```bash
    git clone https://github.com/hva8055/Audit_Script
```
```bash    
    cd Audit_Script
```
2.  **Install all required Python libraries:**
 ```bash   
    pip install -r requirements.txt 
```
3.  **Run the script:**
```bash
    python main.py
```
