# AutoFrida
Frida Android Security Tool is a Python GUI application powered by Frida to perform dynamic and static analysis of Android applications.
It provides an intuitive interface for attaching to processes, monitoring file system, and decrypting app data at runtime. 

# Key Features
  * Attach to running apps or spawn app processes with Frida
  * Load Frida scripts to hook into app processes
  * Monitor file system access in real-time
  * IPC Traffic - watch all IPC traffic made by the app - intents with all their details
  * URI - catch all URI schemes used to exploit DeepLinks
  * Exploit - see exported components and fuzz exported activities
  * Search in classes loaded by the app
  * File explorer -  explore device files, create delete or upload
  * Dump/show used files to PC
  * Bypass root detection, certificate pinning, debugger checks, and more
  * Support for custom scripts
  * Analyze logs automatically - find sensitive data by regexes and alert for matches
  * sign APK files
  
  
# Requirements
  - Frida installed on your machine
  - Frida server running on the Android device
  - USB debugging enabled on the Android device
  - Install python requirements from requiremets.txt
  - Make sure that you have ADB installed and also in PATH
  - Basic knowledge of JavaScript for writing custom scripts (not necessary)


# Usage
  - First, install the requirements
```
pip install requirements.txt
```
 - Then run the app 
```
python autoFrida.py
```
  - Connect an Android device via USB
  - Start the Frida server on the device
  - Enter the package name or select the target app (if you want to attach simply open the app on your phone and click the attach button, the app will automatically will recognize the details)

**How to use?**
  - Use the toolbar buttons to attach to the app process or spawn it
  - Load the built-in Frida scripts by toggle on the wanted scripts or upload a custom script
  - Interact with the app and monitor the output.
  - Generate a report of the security assessment findings
  - The tool provides a terminal view and log file viewer to see the output from Frida scripts, the logs, and the opened files.
  - Save or load previous projects you worked on


# Scripts section
  Hook native methods
  Monitor shared preferences and all files used by the app
  Bypass certificate pinning, root detection etc...
  Write your scripts in JavaScript to extend the functionality.


# Screenshots
## Main screen
![image](https://github.com/n0S3curity/AutoFrida/assets/106635812/97c49cab-34c2-4835-9a31-1a8d7679e561)

## File Manager tab
![image](https://github.com/n0S3curity/AutoFrida/assets/106635812/e7c214aa-b5d6-4cc1-82de-f136b3a1e96a)

## File Explorer tab
![image](https://github.com/n0S3curity/AutoFrida/assets/106635812/6348650e-5ddb-4b38-9e7d-fcbebdd4e5a2)

## Classes tab
![image](https://github.com/n0S3curity/AutoFrida/assets/106635812/29dcec9f-fbd7-4533-91ca-7d67dcf444cf)

## Logs tab
![image](https://github.com/n0S3curity/AutoFrida/assets/106635812/6a02e3d9-4ae9-402a-8397-234e19f1e378)

## Exploit tab
![image](https://github.com/n0S3curity/AutoFrida/assets/106635812/5d453d52-127a-4c8c-94fc-35ac4c25e2e5)


## IPC Traffic tab
![image](https://github.com/n0S3curity/AutoFrida/assets/106635812/029da4fe-0766-4769-bad7-e55daab020dd)

## Device packages tab
![image](https://github.com/n0S3curity/AutoFrida/assets/106635812/e5c342eb-ebeb-4a7c-ba06-5972d4c3b0c4)

## Static analyze
![image](https://github.com/n0S3curity/AutoFrida/assets/106635812/224ccc82-2b56-43aa-afaa-7cc9a9c5bd5e)

## Dynamic analyze 
![image](https://github.com/n0S3curity/AutoFrida/assets/106635812/0edb2e58-e964-46fa-89f8-ecc197d1f2e1)

## Findings export 
![image](https://github.com/n0S3curity/AutoFrida/assets/106635812/ba1096cb-ccc8-4dd9-a4b6-0028a438aa6e)




# Troubleshooting
  - See the Frida documentation for help with setting up the environment and troubleshooting connection issues with devices.
  - Make sure that Frida is running on your phone only when trying to attach - stop Frida in the phone when trying to spawn.
