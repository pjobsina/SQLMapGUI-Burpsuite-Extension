# SQLMap GUI (Burp Suite Extension) 

A SQLMap GUI Python Script, compatible Burp Suite extension that provides a GUI for sqlmap on Windows
<img width="1914" height="927" alt="image" src="https://github.com/user-attachments/assets/7a14f4c8-f8d7-4ffc-84d2-5c5771590992" />


## Features

- Target URL (-u)
- Request file mode (-r)
- Parameter targeting (-p)
- Headers / Cookies / POST body support
- Multi-select --technique
- Enumeration panel (collapsible)
- Dark mode compatible
- Wrapped console output
- Scroll lock
- Timestamped output
- Copy & Save console output
- Windows 10 & 11 compatible

## Requirements

- Burp Suite (Community or Pro)
- Jython standalone JAR
- Python 3.x installed
- sqlmap installed

Before using the extension, make sure these requirements are met:

1. **SQLmap** must be installed on your system. Note: Make sure to clone it outside OneDrive.
```
git clone https://github.com/sqlmapproject/sqlmap
```
2. **Jython** must be configured in **Burp Suite**. Go to Settings > Extensions > Python environment and set the Jython standalone JAR file path.
<img width="1331" height="378" alt="image" src="https://github.com/user-attachments/assets/c96801bc-dfcf-4f9a-bd44-36adb7c7202f" />

3. **SQLMapGUI Script**. Note: Make sure to clone it outside OneDrive.
```
git clone https://github.com/pjobsina/SQLMapGUI-Burpsuite-Extension.git
```

## Installation

1. Open Burp Suite
2. Go to Extensions → Installed
3. Add extension
4. Type: Python
5. Select SQLMapGUI.py
<img width="502" height="153" alt="image" src="https://github.com/user-attachments/assets/f01f049d-7a04-49ae-b2ac-193099f51dc7" />


## Configuration

Edit the following in the script:

```python
PYTHON_EXE = r"C:\Path\To\python.exe"
SQLMAP_PY  = r"C:\Path\To\sqlmap.py"
```

## Usage

- Use Target URL mode (-u)
- Or right-click request → Send to SQLMap
- Expand Enumeration panel when needed
- Run and monitor wrapped output

## Example Screenshot
<img width="1918" height="930" alt="image" src="https://github.com/user-attachments/assets/da0a0f8e-9414-40ce-91fa-659f4fc18d60" />

## Educational Testing Environment

This extension was developed and tested using intentionally vulnerable training platforms provided by:

- PortSwigger Web Security Academy
  <br>https://portswigger.net/web-security

## Responsible Usage

All testing during development was performed against:

- PortSwigger Web Security Academy labs
- Controlled test environments
- Authorized targets only

This tool is intended strictly for educational purposes and authorized penetration testing.

## References

This project builds upon concepts and community research in integrating Burp Suite with sqlmap:

- Yousef Alotaibi, *Burp Suite Integration with SQLMap*
  <br>https://medium.com/@YousefAlotaibi/burp-suite-integration-with-sqlmap-8ee7c65e2a1e

- sqlmap Official Repository
  <br>https://github.com/sqlmapproject/sqlmap
