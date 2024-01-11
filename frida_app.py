import base64
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import tkinter
import traceback
from concurrent.futures import ThreadPoolExecutor
from tkinter import filedialog, messagebox

import customtkinter
import frida


class FridaApp():
    def __init__(self, GUIapp):
        self.device = ''
        self.device_is_connected = False
        self.package_name = ''
        self.name = ''
        self.apk_device_path = ''
        self.data_path = ''
        self.apk_pc_path = ''
        self.script = None
        self.is_apk_pulled = False
        self.used_files = []
        self.regexes = self.load_regexes_from_file('Lists/regexes.json')
        self.secrets = self.load_secrets_from_file('Lists/secrets.txt')
        self.uber_signer_path = 'Uber-signer/uber-signer.jar'
        self.zipalign_path = 'Uber-signer/zipalign.exe'
        self.GUIapp = GUIapp
        self.exported_activities = []
        self.exported_services = []
        self.exported_receivers = []
        self.uri_list = []

    def check_current_activity(self):
        while True:
            show_command = 'adb shell dumpsys window | find "mCurrentFocus"'
            try:
                result = subprocess.run(show_command, shell=True, check=True, capture_output=True, text=True)
                current_activity = result.stdout.strip().split('/')[-1].replace("}", "")
                self.GUIapp.title(f"Current Activity: {current_activity}")
            except Exception as e:
                # self.GUIapp.print_to_console_textBox(text=f"Error occurred check_current_activity function: {traceback.format_exc()}",
                #                                      color='red')
                pass
            time.sleep(1)

    def on_message(self, message, data):
        try:
            # if 'LoggedMessage' not in message:
            #     print("Received message:", message)
            if 'payload' in message:
                payload = message['payload']
                if 'bytes!' in message['payload']:
                    return
                if 'File opened for write' in message['payload']:
                    filename = message['payload'].replace("File opened for write", "").strip()
                    if filename not in self.used_files:
                        self.used_files.append(filename)
                        self.GUIapp.create_new_file_opened(filename)
                        self.GUIapp.print_to_console_textBox(text=f'[Attention] New file opened: {filename}',
                                                             color='orange')
                        self.GUIapp.print_to_files_console_textbox(text=f'[Attention] New file opened: {filename}',
                                                                   color='red')
                if 'file' in payload and 'content' in payload:
                    content = payload['content']
                    if isinstance(content, list) and content is not None:
                        content_string = ''
                        for byte in content:
                            if byte is not None and 0 <= byte <= 0x10FFFF:
                                try:
                                    content_string += chr(byte)
                                except ValueError:
                                    content_string += '?'  # Placeholder character
                            else:
                                content_string += '?'  # Placeholder character for None or out-of-range values
                        self.GUIapp.print_to_files_console_textbox(
                            text=f'File opened for writing: {payload["file"]}', color='green')
                        self.GUIapp.print_to_files_console_textbox(text=content_string)

                if 'LoggedMessage' in payload:
                    Logmessage = payload['LoggedMessage']
                    if "ViewPostIme key 0" in Logmessage or "ViewPostIme key 1" in Logmessage:
                        pass
                    else:
                        self.GUIapp.print_to_logs_console_textbox(f"Log: {Logmessage}")
                        self.analyze_log(message=Logmessage)
                # elif 'LoggedMessage' not in payload:
                #     self.GUIapp.print_to_console_textBox(text=str(message))

                if 'exportedActivities' in payload and 'exportedServices' in payload and 'exportedReceivers' in payload:
                    self.exported_activities = payload['exportedActivities'] + ['Exported Activities']
                    self.exported_services = payload['exportedServices'] + ['Exported Services']
                    self.exported_receivers = payload['exportedReceivers'] + ['Exported Receivers']
                    self.create_exported_components_lists()
                if 'type' in payload:
                    if payload['type'] == 'ClassesSearchResult':
                        if 'payload' in payload:
                            res = payload['payload']
                            print(type(res))
                            if type(res) == list:
                                for i in res:
                                    self.GUIapp.print_to_classes_console_textbox(text=i)
                        else:
                            self.GUIapp.print_to_classes_console_textbox(text="No result",color='red')


                    if payload['type'] == 'URIscheme':
                        if 'data' in payload:
                            organized_data = json.loads(payload['data'])

                            uri_data = organized_data.get('Data', {})
                            if isinstance(uri_data, dict) and 'URI' in uri_data:
                                uri = uri_data['URI']
                                # Check if the URI is not in the list
                                activity = organized_data.get('Activity', '')
                                action = organized_data.get('Action', '')
                                extras = organized_data.get('Extras', '')
                                category = organized_data.get('Categories', '')
                                # Print to ipc textbox the complete activity, action, and extras
                                self.GUIapp.print_to_ipc_textBox(text=f'URI: {uri}', color='orange')
                                if (self.package_name + '/' + activity) in self.exported_activities:
                                    self.GUIapp.print_to_ipc_textBox(text=f'\tActivity (Exported): {activity}',color='green')
                                else:
                                    self.GUIapp.print_to_ipc_textBox(text=f'\tActivity (Not Exported): {activity}')
                                self.GUIapp.print_to_ipc_textBox(text=f'\tAction: {action}\n\tCategories: {category}\n\tExtras: {extras}')
                                self.GUIapp.print_to_console_textBox(text=f"[URI] New URI found! check 'IPC Traffic' tab. ",color='orange')
                                if uri not in self.uri_list:
                                    self.uri_list.append(uri)

                            else:
                                # No URI, which means the activity has opened
                                activity = organized_data.get('Activity', '')
                                action = organized_data.get('Action', '')
                                extras = organized_data.get('Extras', '')
                                # Print to ipc textbox the complete activity, action, and extras
                                if (self.package_name + '/' + activity) in self.exported_activities:
                                    self.GUIapp.print_to_ipc_textBox(text=f'\tActivity opened (Exported): {activity}', color='green')
                                else:
                                    self.GUIapp.print_to_ipc_textBox(text=f'Activity opened (Not Exported): {activity}', color='orange')
                                self.GUIapp.print_to_ipc_textBox(text=f'\tAction: {action}\n\tExtras: {extras}')

                    if payload['type'] == 'ActivityStart':
                        if 'data' in payload:
                            data = json.loads(payload['data'])
                            activity = data.get('Activity', '')
                            action = data.get('Action', '')
                            category = data.get('Category', '')
                            extras = data.get('Extras', '')

                            if 'Activity' in data.keys():
                                if (self.package_name + '/' + activity) in self.exported_activities:
                                    self.GUIapp.print_to_ipc_textBox(text=f'\tActivity opened (Exported): {activity}',
                                                                     color='green')
                                else:
                                    self.GUIapp.print_to_ipc_textBox(text=f'Activity opened (Not Exported): {activity}',
                                                                     color='orange')
                            self.GUIapp.print_to_ipc_textBox(text=f'\tAction: {action}\n\tCategories: {category}\n\tExtras:')

                            if isinstance(extras, dict):
                                for key, val in extras.items():
                                    self.GUIapp.print_to_ipc_textBox(text=f'\t\t{key}: {val}')
                            else:
                                self.GUIapp.print_to_ipc_textBox(text=f'\t\t{extras}')

            else:
                self.GUIapp.print_to_console_textBox(text=str(message))
        except Exception as e:
            pass
            self.GUIapp.print_to_console_textBox(text=f'Error in on_message:\n{traceback.format_exc()}', color='red')

    def create_exported_components_lists(self):
        self.GUIapp.exported_activities_menu.configure(values=self.exported_activities)
        self.GUIapp.exported_services_menu.configure(values=self.exported_services)
        self.GUIapp.exported_receivers_menu.configure(values=self.exported_receivers)
        self.GUIapp.print_to_console_textBox(text='Lists of exported components updated! , check Exploit tab',
                                             color='green')

    def load_regexes_from_file(self, file_path):
        with open(file_path, 'r') as file:
            return json.load(file)

    def load_secrets_from_file(self, file_path):
        with open(file_path, 'r') as file:
            return set(line.strip() for line in file)

    def analyze_log(self, message):
        def match_regexes(text):
            for regex_name, regex_pattern in self.regexes.items():
                if re.search(regex_pattern, text):
                    self.GUIapp.print_to_files_console_textbox(
                        text=f'\n[ATTENTION] Matched regex "{regex_name}" in the log: {text}\n', color='orange')
                    self.GUIapp.print_to_logs_console_textbox(
                        text=f'\n[ATTENTION] Matched regex "{regex_name}" in the log: {text}\n', color='red')
                    self.GUIapp.print_to_console_textBox(
                        text=f'\n[ATTENTION] Matched regex "{regex_name}" in the log: {text}\n', color='red')

        def match_secrets(text):
            for secret in self.secrets:
                encoded_secret = base64.b64encode(secret.encode()).decode()
                if secret in text or encoded_secret in text:
                    if "key 1" in text or "key 0" in text:
                        continue
                    self.GUIapp.print_to_files_console_textbox(
                        text=f'[ATTENTION] Found secret word "{secret}" in the log: {text}', color='orange')
                    self.GUIapp.print_to_console_textBox(
                        text=f'[ATTENTION] Found secret word "{secret}" in the log: {text}', color='red')
                    self.GUIapp.print_to_logs_console_textbox(
                        text=f'[ATTENTION] Found secret word "{secret}" in the log: {text}', color='red')

        with ThreadPoolExecutor() as executor:
            executor.submit(match_regexes, message)
            executor.submit(match_secrets, message)

    def on_device_lost(self):
        try:
            self.device_is_connected = False
            self.GUIapp.print_to_console_textBox(text="Device is lost, trying to reconnect..", color='orange')
        except frida.InvalidOperationError as e:
            self.GUIapp.print_to_console_textBox(text=f"Frida invalid operation error: {e}", color='red')
        except Exception as e:
            self.GUIapp.print_to_console_textBox(text=f"Error in on_device_lost\n{traceback.format_exc()}", color='orange')

    def attach_frida(self):
        try:
            self.try_to_load_device()
            if self.device_is_connected == False:
                self.GUIapp.print_to_console_textBox(text="Device is not connected,try again.", color='orange')
                return
            app = self.device.get_frontmost_application(scope="full")
            if app is not None:
                params = dict(app.parameters)
                if params:
                    if params['sources']:
                        self.apk_device_path = self.GUIapp.app_details_dict["Apk Path"] = params['sources'][0]
                    if params['data-dir']:
                        self.data_path = self.GUIapp.app_details_dict["Data Path"] = params['data-dir']
                self.GUIapp.print_to_console_textBox(
                    text=f"Attaching frida to '{app.name}' , package: {app.identifier} ")
                self.name = self.GUIapp.app_details_dict["App Name"] = app.name
                self.GUIapp.app_name_entry.delete(0, "end")
                self.GUIapp.app_name_entry.insert(0, app.name)
                self.GUIapp.app_name_entry.configure(state="disable")
                self.GUIapp.update_app_name_button.grid()
                self.package_name = self.GUIapp.app_details_dict["Package Name"] = app.identifier
                self.GUIapp.update_details_tab_content()
                self.GUIapp.load_all_tuggled_scripts()
                # ---------------------------
                self.GUIapp.print_to_console_textBox(text="Attaching...")
                # Attach to the running app
                session = self.device.attach(self.name)
                # session = self.device.attach(0)
                self.script = session.create_script(self.GUIapp.script_to_load)
                self.script.on("message", self.on_message)
                self.device.on('lost', self.on_device_lost)
                self.script.load()
                self.GUIapp.print_to_console_textBox(text=f"Successfully attached to '{self.name}'.", color='green')
                self.GUIapp.add_finding_to_finding_tab("Lack of anti-hooking protection")
                self.set_file_explorer_path()
                sys.stdin.read()
        except frida.ProcessNotFoundError as e:
            self.GUIapp.print_to_console_textBox(text=f"Frida Process not found error: {e}",
                                                 color='red')
        except frida.TransportError as e:
            self.GUIapp.print_to_console_textBox(text=f"Frida Transport Error: {e}",
                                                 color='red')
        except frida.ServerNotRunningError:
            self.GUIapp.print_to_console_textBox(text=f"Frida server is closed. click on 'Connect Frida' button.",color='red')
        except Exception as e:
            error_message = str(e)
            if 'device is gone' in error_message:
                self.GUIapp.print_to_console_textBox(text=f"Device is gone, looking for connection.. - {traceback.format_exc()}")
                self.device_is_connected = False
            self.GUIapp.print_to_console_textBox(text=f"Error occurred in attach_frida:\n{traceback.format_exc()}", color='red')



    def spawn_frida(self):
        try:
            if self.device_is_connected == False:
                self.GUIapp.print_to_console_textBox(text="Device is not connected,try again.", color='orange')
                return
            app_name = self.GUIapp.app_name_entry.get()
            if app_name == '':
                self.GUIapp.print_to_console_textBox(text=f"App name is not provided.", color='orange')
                return
            is_app_exist = self.check_if_app_exists_in_device()
            if not is_app_exist:
                self.GUIapp.print_to_console_textBox(text=f"App '{app_name}' didn't found on device.", color='orange')
                return
            self.GUIapp.load_all_tuggled_scripts()
            # -----------------------------------
            self.GUIapp.print_to_console_textBox(text="Spawning...")
            # Spawn the app and attach to it
            pid = self.device.spawn(self.package_name, timeout=60000)
            session = self.device.attach(pid)
            self.script = session.create_script(self.GUIapp.script_to_load)
            self.script.on("message", self.on_message)
            self.device.on('lost', self.on_device_lost)
            self.script.load()
            self.device.resume(pid)
            self.set_file_explorer_path()
            self.GUIapp.print_to_console_textBox(text=f"App: '{self.package_name}' successfully spawned.",
                                                 color='green')
            self.GUIapp.add_finding_to_finding_tab("Lack of anti-hooking protection")
            sys.stdin.read()
        except frida.TransportError as e:
            self.GUIapp.print_to_console_textBox(text=f"Frida transport error {e}", color='red')
        except Exception as e:
            error_message = str(e)
            if 'device is gone' in error_message:
                self.GUIapp.print_to_console_textBox(text=f"Device is gone, looking for connection.. - {traceback.format_exc()}")
                self.device_is_connected = False
            self.GUIapp.print_to_console_textBox(text=f"Error while spawning:\n{traceback.format_exc()}", color='red')

    def detach_frida(self):
        try:
            if self.device_is_connected == False:
                self.GUIapp.print_to_console_textBox(text="Device is not connected, try again.", color='orange')
                return
            if self.script is not None:
                self.script.unload()
                self.script = None
                self.GUIapp.print_to_console_textBox(text=f"Detached from the app, {self.name}:{self.package_name}",
                                                     color='orange')
            else:
                self.GUIapp.print_to_console_textBox(text="No attached script found to detach.", color='orange')
        except frida.InvalidOperationError as e:
            self.GUIapp.print_to_console_textBox(text=f"Frida invalid operation error: {e}",color='red')
        except Exception as e:
            self.GUIapp.print_to_console_textBox(text=f"Error occurred while detaching: {traceback.format_exc()}", color='red')

    def get_list_of_apps(self, mode=''):
        if mode == "all":
            RAL = []
            runnnig_apps = self.device.enumerate_applications()
            for app in runnnig_apps:
                RAL.append(f"{app.name} | {app.identifier}")
            return RAL
        elif mode == "running":
            RAL = []
            runnnig_apps = self.device.enumerate_applications()
            for app in runnnig_apps:
                if app.pid != 0:
                    RAL.append(f"{app.name} | {app.identifier}")
            return RAL

    def load_all_apps(self):
        try:
            if not self.device_is_connected:
                self.device_is_connected == False
                self.GUIapp.print_to_console_textBox(text="Device is not connected,try again.", color='orange')
                return
            self.GUIapp.print_to_console_textBox(text="Loading all apps...")
            running_apps_list = self.get_list_of_apps(mode="all")
            if not running_apps_list:
                self.GUIapp.device_packages_menu.set("No apps found!")
                return
            self.GUIapp.device_packages_menu.configure(values=running_apps_list)
            self.GUIapp.device_packages_menu.set("List updated!")
            self.GUIapp.print_to_console_textBox(text="Done.", color='green')
        except Exception as e:
            self.GUIapp.print_to_console_textBox(text=f"Error occurred while get all running apps from device.\n{traceback.format_exc()}",
                                                 color='red')

    def load_running_apps(self):
        try:
            if not self.device_is_connected:
                self.device_is_connected == False
                self.GUIapp.print_to_console_textBox(text="Device is not connected,try again.", color='orange')
                return
            self.GUIapp.print_to_console_textBox(text="Loading running apps...")
            running_apps_list = self.get_list_of_apps(mode="running")
            if not running_apps_list:
                self.GUIapp.device_packages_menu.set("No apps found!")
                return
            self.GUIapp.device_packages_menu.configure(values=running_apps_list)
            self.GUIapp.device_packages_menu.set("List updated!")
            self.GUIapp.print_to_console_textBox(text="Done.", color='green')
        except Exception as e:
            self.GUIapp.print_to_console_textBox(text=f"Error occurred while get all running apps from device.\n{traceback.format_exc()}",
                                                 color='red')

    def check_if_app_exists_in_device(self):
        try:
            if self.device:
                applications = self.device.enumerate_applications()
                for app in applications:
                    if self.GUIapp.app_name_entry.get() in app.name:
                        self.package_name = app.identifier  # update the package name
                        self.name = app.name  # update the name

                        self.GUIapp.app_details_dict["Package Name"] = app.identifier
                        self.GUIapp.update_details_tab_content()
                        self.GUIapp.print_to_console_textBox(text=f"App '{app.name}' found in device.")
                        return True
                return False
            else:
                self.GUIapp.print_to_console_textBox(text=f"Device is not connected.")
                self.device_is_connected == False
                return
        except frida.InvalidOperationError as e:
            error_message = str(e)
            if 'device is gone' in error_message:
                self.GUIapp.print_to_console_textBox(text=f"Device is gone, looking for connection.. - {traceback.format_exc()}")
                self.device_is_connected = False
        except Exception as e:
            self.GUIapp.print_to_console_textBox(text=f"Error check_if_app_exists_in_device function:\n{traceback.format_exc()}")

    def pull_apk_file_thread(self):
        try:
            self.try_to_load_device()
            if self.device_is_connected == False:
                self.GUIapp.print_to_console_textBox(text="Device is not connected,try again.", color='orange')
                return
            if self.device:
                app = self.device.get_frontmost_application(scope="full")
                if app is not None:
                    params = dict(app.parameters)
                    if params:
                        if params['sources']:
                            self.apk_device_path = self.GUIapp.app_details_dict["Apk Path"] = params['sources'][0]
                        if params['data-dir']:
                            self.data_path = self.GUIapp.app_details_dict["Data Path"] = params['data-dir']
                        self.GUIapp.update_details_tab_content()
                    self.apk_pc_path = os.path.join(os.getcwd(), f"{app.name}.apk").replace(" ", "_")
                    pull_command = f"adb pull {self.apk_device_path} {self.apk_pc_path}"
                    self.GUIapp.print_to_console_textBox(
                        text=f"Going to pull apk file of current running app: '{app.name}'\nfrom: {self.apk_device_path}\nto: {self.apk_pc_path}")
                    subprocess.call(pull_command, shell=True)
                    if os.path.exists(self.apk_pc_path):
                        self.GUIapp.print_to_console_textBox(text="[*] Apk file pulled successfully.", color='green')
                        self.is_apk_pulled = True
                        self.GUIapp.open_apk_button.grid()
                        self.GUIapp.print_to_console_textBox(text="Starting automatic Strings analyze of apk file\nThis may take a few minutes..",
                                                             color='orange')
                        analyze = threading.Thread(target=self.analyze_strings_on_apk_file)
                        analyze.start()
                    else:
                        self.GUIapp.print_to_console_textBox(text="[*] Apk file NOT pulled.", color='orange')
                        # the target_app.is_apk_pulled is already set to False

        except Exception as e:
            self.GUIapp.print_to_console_textBox(text=f"Error occurred in pull_apk_file function: \n{traceback.format_exc()}", color='red')

    def analyze_strings_on_apk_file(self):
        pass
        # def match_regexes_strings(result):
        #     for regex_name, regex_pattern in self.regexes.items():
        #         if re.search(regex_pattern, result):
        #             self.GUIapp.print_to_all_consoles(
        #                 text=f'\n[Strings] Found regex pattern "{regex_name}" in Strings: {result}\n', color='red')
        #
        # def match_secret_strings(result):
        #     for secret in self.secrets:
        #         encoded_secret = base64.b64encode(secret.encode()).decode()
        #         if secret in result or encoded_secret in result:
        #             self.GUIapp.print_to_all_consoles(
        #                 text=f'\n[Strings] Found secret word "{secret}" in Strings: {result}\n', color='red')
        #
        # try:
        #     if self.apk_pc_path != '' and os.path.exists(self.apk_pc_path):
        #         strings_command = f"strings {self.apk_pc_path}"
        #         strings_result = subprocess.check_output(strings_command, shell=True, encoding='utf-8')
        #         match_regexes_strings(strings_result)
        #         match_secret_strings(strings_result)
        # except Exception as e:
        #     error_msg = f"Error in analyze_apk_strings function: {traceback.format_exc()}"
        #     traceback_msg = traceback.format_exc()
        #     full_error_msg = f"{error_msg}\n\nTraceback:\n{traceback_msg}"
        #     self.GUIapp.print_to_console_textBox(text=full_error_msg, color='red')

    def try_to_load_device(self):
        try:
            self.device = frida.get_usb_device()
            if self.device:
                self.device_is_connected = True
                new_details = {
                    "Device Name": self.device.name,
                    "Device ID": self.device.id,
                    "Device Connection Type": self.device.type
                }
                for key, value in new_details.items():
                    if key in self.GUIapp.app_details_dict and self.GUIapp.app_details_dict[key] != value:
                        self.GUIapp.app_details_dict[key] = value
                    elif key not in self.GUIapp.app_details_dict:
                        self.GUIapp.app_details_dict[key] = value
                self.GUIapp.print_to_console_textBox(text="[*] Device is connected.", color='green')
                self.GUIapp.update_details_tab_content()
            else:
                self.device_is_connected = False
        except frida.InvalidArgumentError:
            self.device_is_connected = False
            pass
        except frida.ServerNotRunningError:
            self.GUIapp.print_to_console_textBox(text="[-] Frida server is not running. Please start it.",
                                                 color='orange')
            pass
        except frida.InvalidOperationError as e:
            error_message = str(e)
            if 'device is gone' in error_message:
                self.GUIapp.print_to_console_textBox(text=f"Device is gone, looking for connection.. - {traceback.format_exc()}")
                self.device_is_connected = False

    def check_if_device_is_connected(self):
        while True:
            try:
                if self.device_is_connected == False:
                    self.try_to_load_device()  # try to load device
                time.sleep(1)
            except Exception as e:
                time.sleep(1)

    def take_screenshot(self):
        if self.device_is_connected:
            try:
                if not os.path.exists("Screenshots"):
                    os.makedirs("Screenshots")
                existing_files = [filename for filename in os.listdir("Screenshots") if
                                  filename.startswith("screenshot_")]
                existing_counters = [int(filename.split("_")[1].split(".")[0]) for filename in existing_files]
                counter = max(existing_counters) + 1 if existing_counters else 1
                screenshot_path = f"Screenshots/screenshot_{counter}.png"
                subprocess.run(["adb", "exec-out", "screencap", "-p", ">", screenshot_path], shell=True, check=True)
                self.GUIapp.print_to_console_textBox(
                    text=f"Screenshot taken successfully and saved as '{screenshot_path}'.",
                    color='green')
            except subprocess.CalledProcessError as e:
                self.GUIapp.print_to_console_textBox(text=f"Error: Unable to take screenshot - {traceback.format_exc()}", color='red')
                self.GUIapp.print_to_console_textBox(text=f"trying to reconnect", color='red')
                self.try_to_load_device()
        else:
            self.GUIapp.print_to_console_textBox(text=f"Error: Device is not connected, trying to reconnect.",
                                                 color='red')
            self.try_to_load_device()

    def run_frida_in_device(self):
        self.GUIapp.print_to_console_textBox(text=f"[ATTENTION] Make sure that frida-server is in /data/local/tmp/\nGoing to kill running frida before starting again..",
                                             color='orange')
        stop_command = 'adb shell su -c "pkill frida-server"'
        subprocess.run(stop_command, shell=True)
        list_command = 'adb shell "cd /data/local/tmp && ls frida-server*"'
        list_process = subprocess.Popen(list_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = list_process.communicate()
        if stderr:
            self.GUIapp.print_to_console_textBox(text=f"Error occurred: {stderr.decode()}", color='red')
            return
        filename = stdout.decode().strip()
        if filename:
            run_command = f'adb shell su -c "./data/local/tmp/{filename} &"'
            subprocess.Popen(run_command, shell=True)
            self.GUIapp.print_to_console_textBox(text=f"'{filename}' started in the background.", color='green')
        else:
            self.GUIapp.print_to_console_textBox(
                text="No 'frida-server' file found in /data/local/tmp directory.\n make sure that there is file starts with 'frida-server' exists in /data/local/tmp and the file has executable privileges.",
                color='red')

    def kill_frida_in_device(self):
        ps_command = "adb shell ps -e | findstr frida-server"
        ps_process = subprocess.Popen(ps_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ps_output, _ = ps_process.communicate()

        # Extract the PID from the output
        pid = None
        if ps_output:
            ps_lines = ps_output.decode().splitlines()
            if len(ps_lines) > 0:
                # Extract the PID from the output
                pid = ps_lines[0].split()[1]

        if pid:
            # Kill the frida-server process using the obtained PID
            kill_command = f'adb shell su -c "kill -9 {pid}"'
            subprocess.run(kill_command, shell=True)
            self.GUIapp.print_to_console_textBox(text=f"Frida-server killed.", color='orange')
        else:
            self.GUIapp.print_to_console_textBox(text=f"Frida-server process not found.(maybe already killed)", color='red')

    def sign_apk_file(self, apk_path):
        apk_copy_path = os.path.join(os.path.dirname(apk_path), 'apk.apk')
        shutil.copy(apk_path, apk_copy_path)
        sign_command = f"java -jar {self.uber_signer_path} -a {apk_copy_path} -o {os.getcwd()} --zipAlignPath {self.zipalign_path} --allowResign"
        try:
            subprocess.Popen(sign_command, shell=True, check=True)
            self.GUIapp.print_to_console_textBox(
                text=f"APK signed successfully. path: {os.path.join(os.getcwd(), 'apk-aligned-debugSigned.apk')}",
                color='green')
            os.remove(apk_copy_path)
        except subprocess.CalledProcessError as e:
            self.GUIapp.print_to_console_textBox(text=f"Error occurred while signing APK: {traceback.format_exc()}", color='red')

    def ls_directory_from_device(self):
        path_to_cat = self.GUIapp.file_explorer_entry.get()
        if path_to_cat.endswith("/"):
            children = self.GUIapp.scrollable_file_explorer.winfo_children()
            for widget in children:
                widget.destroy()
            time.sleep(0.5)
            command = f"adb shell su -c 'ls -l {path_to_cat}'"  # Use 'ls -l' to get detailed information
            try:
                result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
                file_list = result.stdout.splitlines()

                for i, file_info in enumerate(file_list):
                    # Splitting the ls -l output into columns
                    file_info_parts = file_info.split()
                    if len(file_info_parts) >= 8:
                        file_type, filename = file_info_parts[0], file_info_parts[-1]
                        if file_type.startswith("d"):
                            # Directory: Add "Open" button
                            label = customtkinter.CTkLabel(self.GUIapp.scrollable_file_explorer, text=filename,
                                                           font=customtkinter.CTkFont(size=15))
                            label.grid(row=i, column=0, padx=0, pady=(5, 5), sticky="w")
                            open_button = customtkinter.CTkButton(master=self.GUIapp.scrollable_file_explorer,
                                                                  text="Open", width=20,
                                                                  command=lambda path=filename: self.open_directory(
                                                                      path))
                            open_button.grid(row=i, column=1, padx=5, pady=(5, 5), sticky="ew")
                            open_button.configure(fg_color='#0067CF')
                        else:
                            # File: Add "Show" button
                            label = customtkinter.CTkLabel(self.GUIapp.scrollable_file_explorer, text=filename,
                                                           font=customtkinter.CTkFont(size=15))
                            label.grid(row=i, column=0, padx=0, pady=(5, 5), sticky="w")
                            show_button = customtkinter.CTkButton(master=self.GUIapp.scrollable_file_explorer,
                                                                  text="Show", width=20,
                                                                  command=lambda path=filename: self.show_file(path))
                            show_button.grid(row=i, column=1, padx=5, pady=(5, 5), sticky="ew")
                            show_button.configure(fg_color='#47BB00')

                            delete_button = customtkinter.CTkButton(master=self.GUIapp.scrollable_file_explorer,
                                                                    text="Delete", width=20,
                                                                    command=lambda path=filename: self.delete_file(
                                                                        path))
                            delete_button.grid(row=i, column=2, padx=5, pady=(5, 5), sticky="ew")
                            delete_button.configure(fg_color='red')

            except Exception as e:
                self.GUIapp.print_to_console_textBox(text=f"[FILE EXPLORER ERROR] Error:\n {traceback.format_exc()}", color='red')

    def open_directory(self, directory_name):
        dest = self.GUIapp.file_explorer_entry.get()
        new_path = f"{dest}{directory_name}/"
        self.GUIapp.file_explorer_entry.delete(0, 'end')
        self.GUIapp.file_explorer_entry.insert(0, new_path)
        self.ls_directory_from_device()

    def show_file(self, file_name):
        dest = self.GUIapp.file_explorer_entry.get()
        filePath = os.path.join(dest, file_name)
        if dest != '':
            command = f'adb shell su -c "cat {filePath}"'
            result = subprocess.run(command, capture_output=True, text=True, shell=True)
            file_content = result.stdout.strip()
            self.GUIapp.print_to_files_console_textbox(text=f'File content: {filePath}', color='green')
            self.GUIapp.print_to_files_console_textbox(text=file_content)
            self.GUIapp.consoles_tabview.set("File Manager")

    def delete_file(self, path):
        dest = self.GUIapp.file_explorer_entry.get()
        filePath = os.path.join(dest, path)
        confirmed = messagebox.askokcancel("Confirmation", f"Are you sure you want to delete '{path}'?")
        if confirmed and dest != '':
            command = f"adb shell su -c 'rm {filePath}'"
            subprocess.run(command, shell=True)
            self.GUIapp.print_to_console_textBox(text=f'File deleted successfully: {filePath}', color='green')
            self.ls_directory_from_device()

    def upload_file(self):
        file_path = filedialog.askopenfilename()
        file_name = file_path.split("/")[-1]
        if file_path:
            destination_path = self.GUIapp.file_explorer_entry.get()
            if destination_path:
                try:
                    adb_command = f"adb push {file_path} /sdcard/{file_name}"
                    subprocess.run(adb_command, shell=True, check=True)
                    adb_command = f"adb shell su -c 'mv /sdcard/{file_name} {destination_path}'"
                    subprocess.run(adb_command, shell=True, check=True)
                    self.GUIapp.print_to_console_textBox(text=f'File uploaded successfully: {file_path}', color='green')
                    self.ls_directory_from_device()
                except subprocess.CalledProcessError as e:
                    self.GUIapp.print_to_console_textBox(text=f'[FILE EXPLORER ERROR] Error uploading file: {traceback.format_exc()}', color='red')
                    self.GUIapp.consoles_tabview.set("Console")
            else:
                self.GUIapp.print_to_console_textBox(text='[FILE EXPLORER ERROR] Please provide a destination path.', color='orange')
                self.GUIapp.consoles_tabview.set("Console")

    def create_folder(self):
        dialog = customtkinter.CTkInputDialog(text="Enter Folder Name\nThe folder will be created at the current path.",
                                              title="Create Folder")
        folder_name = dialog.get_input()
        destination_path = self.GUIapp.file_explorer_entry.get()
        if folder_name is not None and destination_path != '':
            adb_command = f"adb shell su -c 'mkdir {destination_path}{folder_name}'"
            subprocess.run(adb_command, shell=True)
        else:
            self.GUIapp.print_to_console_textBox(
                text=f'[FILE EXPLORER ERROR] Path is empty! go to destination path and then create the folder.', color='red')
            self.GUIapp.consoles_tabview.set("Console")

    def set_file_explorer_path(self):
        if self.data_path != '':
            self.GUIapp.file_explorer_entry.delete(0, 'end')
            self.GUIapp.file_explorer_entry.insert(0, self.data_path + '/')
            self.ls_directory_from_device()

    def fuzz_exported_activities(self):
        if not len(self.exported_activities) == 0:
            self.GUIapp.stop_fuzz_activities = False
            for activity in self.exported_activities:
                if activity != "Exported Activities":
                    if not self.GUIapp.stop_fuzz_activities:
                        try:
                            command = f"adb shell am start -n {activity}"
                            subprocess.run(command,shell=True)
                            self.GUIapp.print_to_exploit_textBox(text=f"Activity opened:{activity}", color='green')
                            time.sleep(3)
                        except Exception as e:
                            self.GUIapp.print_to_exploit_textBox(text=f"Activity Fail: {traceback.format_exc()}", color='red')
                    else:
                        self.GUIapp.print_to_exploit_textBox(text=f"Fuzzing stopped by User", color='red')
                        break
                else:
                    self.GUIapp.print_to_exploit_textBox(text=f"Fuzzing finished.", color='green')
        else:
            self.GUIapp.print_to_exploit_textBox(text=f"No exported activities list found (did you attached?)\nif you already attached maybe there is no exported activities.", color='orange')

    def search_class(self):
        string_to_search = self.GUIapp.classes_entry.get()
        if  string_to_search != '':
            if self.script != '' and self.script is not None:
                self.GUIapp.print_to_classes_console_textbox(text="Classes Console ",color='green')
                self.GUIapp.print_to_classes_console_textbox(text="Searching for: " + self.GUIapp.classes_entry.get())
                self.GUIapp.print_to_classes_console_textbox(text="Results:")
                self.script.post({'type': 'classToSearch', 'payload': string_to_search})
            else:
                attach_thread = threading.Thread(target=self.attach_frida)
                attach_thread.start()
                self.GUIapp.print_to_classes_console_textbox(text="You are not attached to any app, attaching..",color='red')
                time.sleep(3)
                self.search_class()