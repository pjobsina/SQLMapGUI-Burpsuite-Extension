# SQLMap GUI (Burp Suite Extension) 

A compact, compatible Burp Suite extension that provides a GUI for sqlmap on Windows 11

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
- Windows 11 compatible

## Requirements

- Burp Suite (Community or Pro)
- Jython standalone JAR
- Python 3.x installed
- sqlmap installed

Before using the extension, make sure these requirements are met:

1. SQLmap must be installed on your system. 
<br>Note: Make sure to clone it outside OneDrive.
```
git clone https://github.com/sqlmapproject/sqlmap
```
2. Jython must be configured in Burp Suite. 
<br>Go to Settings > Extensions > Python environment and set the Jython standalone JAR file path.
![alt text](image.png)

3. SQLMapGUI Script.
<br>Note: Make sure to clone it outside OneDrive.
```
git clone 
```

## Installation

1. Open Burp Suite
2. Go to Extensions → Installed
3. Add extension
4. Type: Python
5. Select SQLMapGUI.py

![alt text](image-1.png)

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

![alt text](image-2.png)
![alt text](image-3.png)

## Educational Testing Environment

This extension was developed and tested using intentionally vulnerable training platforms provided by:

- PortSwigger Web Security Academy  
  https://portswigger.net/web-security

The labs were used to:

- Validate SQL injection detection workflows
- Test parameter targeting with `-p`
- Evaluate header and cookie injection scenarios
- Verify enumeration logic (`--dbs`, `--tables`, `--columns`, `--dump`)
- Simulate real-world attack chains in a controlled environment

## Responsible Usage

All testing during development was performed against:

- PortSwigger Web Security Academy labs
- Controlled test environments
- Authorized targets only

This tool is intended strictly for educational purposes and authorized penetration testing.

## References

This project builds upon concepts and community research in integrating Burp Suite with sqlmap:

- Yousef Alotaibi, *Burp Suite Integration with SQLMap*  
  https://medium.com/@YousefAlotaibi/burp-suite-integration-with-sqlmap-8ee7c65e2a1e

- sqlmap Official Repository  
  https://github.com/sqlmapproject/sqlmap
