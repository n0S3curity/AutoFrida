# AutoFrida
Frida Android Security Tool is a Python GUI application powered by Frida to perform dynamic and static analysis of Android applications.
It provides an intuitive interface for attaching to processes, monitoring file system and decrypting app data at runtime. 

# Key Features
  * Attach to running apps or spawn app processes with Frida
  * Load Frida scripts to hook into app processes
  * Monitor file system access in real-time
  * Dump used files to PC
  * Bypass root detection and certificate pinning
  * Support for custom scripts
  * Analyze logs automaticlly - find sensitive data by regexes and alert for matches

# Requirements
  - Frida installed on your machine
  - Frida server running on the Android device
  - USB debugging enabled on the Android device
  - Install python requirements from requiremets.txt
  - Make sure that you have adb working
  - Basic knowledge of JavaScript for writing custom scripts (not neccessary)


# Usage
  - First install the requirements
```
pip install requirements.txt
```
 - Then run the app 
```
pyhton app.py
```
  - Connect an Android device via USB
  - Start the Frida server on the device
  - Enter the package name or select the target app (if yoou want to attach simply open the app on your phone and click the attach button, the app will automaticlly will recognize the details)

**How to use?**
  - Use the toolbar buttons to attach to the app process or spawn it
  - Load the built-in Frida scripts by toggle on the wanted scripts or upload a custom script
  - Interact with the app and monitor the output.
  - Generate a report of the security assessment findings
  - The tool provides a terminal view and log file viewer to see the output from Frida scripts, the logs and the opened files.
  - Save or load previous projects you worked on


# Scripts section
  Hook native methods
  Monitor shared preferences and all files used by thye app
  Bypass certificate pinning, root detection etc..
  Write your own scripts in JavaScript to extend the functionality.

# Troubleshooting
  - See the Frida documentation for help with setting up the environment and troubleshooting connection issues with devices.
  - Make sure that frida is running on your phone only when trying to attach - stop frida in phone when trying to spawn.
