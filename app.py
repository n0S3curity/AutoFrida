import shlex
import threading
import tkinter
import tkinter.messagebox
from tkinter import filedialog, messagebox
import pickle
import customtkinter
import frida
import os
import subprocess
import sys
import time
import traceback


class FridaApp():
    def __init__(self):
        self.device = ''
        self.device_is_connected = False
        self.package_name = ''
        self.name = ''
        self.apk_device_path = ''
        self.data_path = ''
        self.apk_pc_path = ''
        self.is_apk_pulled = False
        self.used_files = []

    def on_message(self, message, data):
        try:
            if 'payload' in message:
                payload = message['payload']
                if 'bytes!' in message['payload']:
                    return
                if 'File opened for write' in message['payload']:
                    filename = message['payload'].replace("File opened for write", "").strip()
                    if filename not in self.used_files:
                        self.used_files.append(filename)
                        GUIapp.create_new_file_opened(filename)
                        GUIapp.print_to_console_textBox(text=f'[Attention] New file opened: {filename}', color='orange')
                        GUIapp.print_to_files_console_textbox(text=f'[Attention] New file opened: {filename}',
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
                        GUIapp.print_to_files_console_textbox(
                            text=f'File opened for writing: {payload["file"]}', color='green')
                        GUIapp.print_to_files_console_textbox(text=content_string)

                if 'LoggedMessage' in payload:
                    Logmessage = payload['LoggedMessage']
                    GUIapp.print_to_logs_console_textbox(f"Log: {Logmessage}")
                    self.analayze_log(message=Logmessage)
                else:
                    GUIapp.print_to_console_textBox(text=str(message))
            else:
                GUIapp.print_to_console_textBox(text=str(message))
        except Exception as e:
            GUIapp.print_to_console_textBox(text=f'Error in on_message:\n{e}', color='red')

    def analayze_log(self,message):
        pass

    def on_device_lost(self):
        try:
            self.device_is_connected = False
            GUIapp.print_to_console_textBox(text="Device is lost, trying to reconnect..", color='orange')
        except Exception as e:
            GUIapp.print_to_console_textBox(text=f"Error in on_device_lost\n{e}", color='orange')

    def attach_frida(self):
        try:
            self.try_to_load_device()
            if self.device_is_connected == False:
                GUIapp.print_to_console_textBox(text="Device is not connected,try again.", color='orange')
                return
            app = self.device.get_frontmost_application(scope="full")
            if app is not None:
                GUIapp.print_to_console_textBox(text=f"Attaching frida to '{app.name}' , package: {app.identifier} ")
                self.name = GUIapp.app_details_dict["App Name"] = app.name
                GUIapp.app_name_entry.delete(0, "end")
                GUIapp.app_name_entry.insert(0, app.name)
                GUIapp.app_name_entry.configure(state="disable")
                GUIapp.update_app_name_button.grid()
                self.package_name = GUIapp.app_details_dict["Package Name"] = app.identifier
                GUIapp.update_details_tab_content()
                GUIapp.load_all_tuggled_scripts()
                # ---------------------------
                GUIapp.print_to_console_textBox(text="Attaching...")
                # Attach to the running app
                session = self.device.attach(self.name)
                script = session.create_script(GUIapp.script_to_load)
                script.on("message", self.on_message)
                self.device.on('lost', self.on_device_lost)
                script.load()
                GUIapp.print_to_console_textBox(text=f"Successfully attached to '{self.name}'.", color='green')
                GUIapp.add_finding_to_finding_tab("Lack of anti-hooking protection")
                sys.stdin.read()
        except Exception as e:
            error_message = str(e)
            if 'device is gone' in error_message:
                GUIapp.print_to_console_textBox(text=f"Device is gone, looking for connection.. - {e}")
                self.device_is_connected = False
            GUIapp.print_to_console_textBox(text=f"Error occurred:\n{e}", color='red')

    def spawn_frida(self):
        try:

            if self.device_is_connected == False:
                GUIapp.print_to_console_textBox(text="Device is not connected,try again.", color='orange')
                return
            app_name = GUIapp.app_name_entry.get()
            if app_name == '':
                GUIapp.print_to_console_textBox(text=f"App name is not provided.", color='orange')
                return
            is_app_exist = self.check_if_app_exists_in_device()
            if not is_app_exist:
                GUIapp.print_to_console_textBox(text=f"App '{app_name}' didn't found on device.", color='orange')
                return
            GUIapp.load_all_tuggled_scripts()
            # -----------------------------------
            GUIapp.print_to_console_textBox(text="Spawning...")
            # Spawn the app and attach to it
            pid = self.device.spawn(self.package_name, timeout=60000)
            session = self.device.attach(pid)
            script = session.create_script(GUIapp.script_to_load)
            script.on("message", self.on_message)
            self.device.on('lost', self.on_device_lost)
            script.load()
            self.device.resume(pid)
            GUIapp.print_to_console_textBox(text=f"App: '{frap.package_name}' successfully spawned.", color='green')
            GUIapp.add_finding_to_finding_tab("Lack of anti-hooking protection")
            sys.stdin.read()

        except Exception as e:
            error_message = str(e)
            if 'device is gone' in error_message:
                GUIapp.print_to_console_textBox(text=f"Device is gone, looking for connection.. - {e}")
                self.device_is_connected = False
            GUIapp.print_to_console_textBox(text=f"Error while spawning:\n{e}", color='red')

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
                GUIapp.print_to_console_textBox(text="Device is not connected,try again.", color='orange')
                return
            GUIapp.print_to_console_textBox(text="Loading all apps...")
            running_apps_list = self.get_list_of_apps(mode="all")
            if not running_apps_list:
                GUIapp.device_packages_menu.set("No apps found!")
                return
            GUIapp.device_packages_menu.configure(values=running_apps_list)
            GUIapp.device_packages_menu.set("List updated!")
            GUIapp.print_to_console_textBox(text="Done.", color='green')
        except Exception as e:
            GUIapp.print_to_console_textBox(text=f"Error occurred while get all running apps from device.\n{e}",
                                            color='red')

    def load_running_apps(self):
        try:
            if not frap.device_is_connected:
                self.device_is_connected == False
                GUIapp.print_to_console_textBox(text="Device is not connected,try again.", color='orange')
                return
            GUIapp.print_to_console_textBox(text="Loading running apps...")
            running_apps_list = self.get_list_of_apps(mode="running")
            if not running_apps_list:
                GUIapp.device_packages_menu.set("No apps found!")
                return
            GUIapp.device_packages_menu.configure(values=running_apps_list)
            GUIapp.device_packages_menu.set("List updated!")
            GUIapp.print_to_console_textBox(text="Done.", color='green')
        except Exception as e:
            GUIapp.print_to_console_textBox(text=f"Error occurred while get all running apps from device.\n{e}",
                                            color='red')

    def check_if_app_exists_in_device(self):
        try:
            if self.device:
                applications = self.device.enumerate_applications()
                for app in applications:
                    if GUIapp.app_name_entry.get() in app.name:
                        self.package_name = app.identifier  # update the package name
                        self.name = app.name  # update the name

                        GUIapp.app_details_dict["Package Name"] = app.identifier
                        GUIapp.update_details_tab_content()
                        GUIapp.print_to_console_textBox(text=f"App '{app.name}' found in device.")
                        return True
                return False
            else:
                GUIapp.print_to_console_textBox(text=f"Device is not connected.")
                self.device_is_connected == False
                return
        except frida.InvalidOperationError as e:
            error_message = str(e)
            if 'device is gone' in error_message:
                GUIapp.print_to_console_textBox(text=f"Device is gone, looking for connection.. - {e}")
                self.device_is_connected = False
        except Exception as e:
            GUIapp.print_to_console_textBox(text=f"Error check_if_app_exists_in_device function:\n{e}")

    def pull_apk_file_thread(self):
        try:
            self.try_to_load_device()
            if self.device_is_connected == False:
                GUIapp.print_to_console_textBox(text="Device is not connected,try again.", color='orange')
                return
            if self.device:
                app = self.device.get_frontmost_application(scope="full")
                if app is not None:
                    params = dict(app.parameters)
                    if params:
                        if params['sources']:
                            self.apk_device_path = GUIapp.app_details_dict["Apk Path"] = params['sources'][0]
                        if params['data-dir']:
                            self.data_path = GUIapp.app_details_dict["Data Path"] = params['data-dir']
                        GUIapp.update_details_tab_content()
                    self.apk_pc_path = os.path.join(os.getcwd(), f"{app.name}.apk")
                    pull_command = f"adb pull {self.apk_device_path} {self.apk_pc_path}"
                    GUIapp.print_to_console_textBox(
                        text=f"Going to pull apk file of current running app: '{app.name}'\nfrom: {self.apk_device_path}\nto: {self.apk_pc_path}")
                    subprocess.call(pull_command, shell=True)
                    if os.path.exists(self.apk_pc_path):
                        GUIapp.print_to_console_textBox(text="[*] Apk file pulled successfully.", color='green')
                        self.is_apk_pulled = True
                        GUIapp.open_apk_button.grid()
                    else:
                        GUIapp.print_to_console_textBox(text="[*] Apk file NOT pulled.", color='orange')
                        # the target_app.is_apk_pulled is already set to False

        except Exception as e:
            GUIapp.print_to_console_textBox(text=f"Error occurred in pull_apk_file function: \n{e}", color='red')

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
                    if key in GUIapp.app_details_dict and GUIapp.app_details_dict[key] != value:
                        GUIapp.app_details_dict[key] = value
                    elif key not in GUIapp.app_details_dict:
                        GUIapp.app_details_dict[key] = value
                GUIapp.print_to_console_textBox(text="[*] Device is connected.", color='green')
                GUIapp.update_details_tab_content()
            else:
                self.device_is_connected = False
        except frida.InvalidArgumentError:
            self.device_is_connected = False
            pass
        except frida.ServerNotRunningError:
            GUIapp.print_to_console_textBox(text="[-] Frida server is not running. Please start it.", color='orange')
            pass
        except frida.InvalidOperationError as e:
            error_message = str(e)
            if 'device is gone' in error_message:
                GUIapp.print_to_console_textBox(text=f"Device is gone, looking for connection.. - {e}")
                self.device_is_connected = False

    def check_if_device_is_connected(self):
        while True:
            try:
                if self.device_is_connected == False:
                    self.try_to_load_device()  # try to load device
                time.sleep(1)
            except Exception as e:
                time.sleep(1)


class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        self.wanted_scripts = []  # list of final wanted name of scripts - will be loaded to self.script_to_load string
        self.script_to_load = ""  # final script combined
        self.scripts = {}  # scriptname : script content
        self.scrollable_frame_switches = {}  # scriptname : switch of the script
        self.scriptSwitchRow = 1
        self.scrollable_findings_row = 2

        self.scrollable_files_row = 1

        self.findings = []
        self.app_details_dict = {}
        self.default_bypasses_scripts = {
            "Android_file_guard": """
        Java.perform(function() {
            var openedfile = "";
            var data = {
                "file": "",
                "content": []
            };
            var isOpen = false;
            var index = 0;

            var fos = Java.use('java.io.FileOutputStream');

            var fos_construct_2 = fos.$init.overload('java.lang.String');
            var fos_construct_3 = fos.$init.overload('java.io.File');
            var fos_construct_4 = fos.$init.overload('java.lang.String', 'boolean');
            var fos_construct_5 = fos.$init.overload('java.io.File', 'boolean');

            var fos_write_1 = fos.write.overload('[B', 'int', 'int');

            var fos_close = fos.close;

            function dump(data) {
                var tmp_name = openedfile.split("/");
                tmp_name = tmp_name[tmp_name.length - 1];
                data["file"] = tmp_name;
                send(data);
                data["content"] = [];
                index = 0;
            }

            fos_construct_2.implementation = function(file) {
                var filename = file;
                if (openedfile != filename) {
                    openedfile = filename;
                    send("File opened for write " + filename);
                    isOpen = true;
                }
                return fos_construct_2.call(this, file);
            }

            fos_construct_3.implementation = function(file) {
                var filename = file.getAbsolutePath();
                if (openedfile != filename) {
                    openedfile = filename;
                    send("File opened for write " + filename);
                    isOpen = true;
                }
                return fos_construct_3.call(this, file);
            }

            fos_construct_4.implementation = function(file, true_false) {
                var filename = file;
                if (openedfile != filename) {
                    openedfile = filename;
                    send("File opened for write " + filename);
                    isOpen = true;
                }
                return fos_construct_4.call(this, file, true_false);
            }

            fos_construct_5.implementation = function(file, true_false) {
                var filename = file.getAbsolutePath()
                if (openedfile != filename) {
                    openedfile = filename;
                    send("File opened for write " + filename);
                    isOpen = true;
                }
                return fos_construct_5.call(this, file, true_false);
            }

            fos_write_1.implementation = function(arr, offset, length) {
                var i = 0;
                for (i = offset; i < length; i = i + 1) {
                    data["content"][index] = arr[i];
                    index = index + 1;
                }
                return fos_write_1.call(this, arr, offset, length);
            }

            fos_close.implementation = function() {
                dump(data);
                return fos_close.call(this);
            }

        });
        """,
            "Android_crypto_bypass": """function bin2ascii(array) {
    var result = [];

    for (var i = 0; i < array.length; ++i) {
        result.push(String.fromCharCode( // hex2ascii part
            parseInt(
                ('0' + (array[i] & 0xFF).toString(16)).slice(-2), // binary2hex part
                16
            )
        ));
    }
    return result.join('');
}

function bin2hex(array, length) {
    var result = "";

    length = length || array.length;

    for (var i = 0; i < length; ++i) {
        result += ('0' + (array[i] & 0xFF).toString(16)).slice(-2);
    }
    return result;
}

Java.perform(function() {
    Java.use('javax.crypto.spec.SecretKeySpec').$init.overload('[B', 'java.lang.String').implementation = function(key, spec) {
        send("KEY: " + bin2hex(key) + " | " + bin2ascii(key));
        return this.$init(key, spec);
    };

    Java.use('javax.crypto.Cipher')['getInstance'].overload('java.lang.String').implementation = function(spec) {
        send("CIPHER: " + spec);
        return this.getInstance(spec);
    };

    Java.use('javax.crypto.Cipher')['doFinal'].overload('[B').implementation = function(data) {
        send("Gotcha!");
        send(bin2ascii(data));
        return this.doFinal(data);
    };
});""",
            "Android_exported_components": r"""function main() {
    Java.perform(function() {
        var ActivityThread = Java.use("android.app.ActivityThread");
        var PackageManager = Java.use("android.content.pm.PackageManager");

        // Get the current application context
        var context = ActivityThread.currentApplication().getApplicationContext();
        var packageName = context.getPackageName();
        var packageInfo = context.getPackageManager().getPackageInfo(packageName,
            PackageManager.GET_ACTIVITIES.value | PackageManager.GET_SERVICES.value | PackageManager.GET_RECEIVERS.value
        );

        send("\n[+] Package Name: " + packageName);

        function logExportedComponents(componentInfoArray, componentType) {
            if (componentInfoArray) {
                for (var i = 0; i < componentInfoArray.length; i++) {
                    var component = componentInfoArray[i];
                    if (component.exported.value) {
                        send("  [-] Exported " + componentType + " " + packageName + "/" + component.name.value);
                    }
                }
            }
        }

        send("\n[+] Exported Activities:");
        logExportedComponents(packageInfo.activities.value, "Activity: ");

        send("\n[+] Exported Services:");
        logExportedComponents(packageInfo.services.value, "Service: ");

        send("\n[+] Exported Broadcast Receivers:");
        logExportedComponents(packageInfo.receivers.value, "Broadcast Receiver: ");

        send("\n[+] Done.");
    });
}

setTimeout(function() {
    Java.scheduleOnMainThread(main);
}, 50);""",
            "Android_root_detection_bypass":"""/*
Original author: Daniele Linguaglossa
28/07/2021 -    Edited by Simone Quatrini
                Code amended to correctly run on the latest frida version
        		Added controls to exclude Magisk Manager
*/

Java.perform(function() {
    var RootPackages = ["com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu",
        "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su", "com.koushikdutta.rommanager",
        "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
        "de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
        "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "me.phh.superuser",
        "eu.chainfire.supersu.pro", "com.kingouser.com", "com.topjohnwu.magisk"
    ];

    var RootBinaries = ["su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk", "SuperSu.apk", "magisk"];

    var RootProperties = {
        "ro.build.selinux": "1",
        "ro.debuggable": "0",
        "service.adb.root": "0",
        "ro.secure": "1"
    };

    var RootPropertiesKeys = [];

    for (var k in RootProperties) RootPropertiesKeys.push(k);

    var PackageManager = Java.use("android.app.ApplicationPackageManager");

    var Runtime = Java.use('java.lang.Runtime');

    var NativeFile = Java.use('java.io.File');

    var String = Java.use('java.lang.String');

    var SystemProperties = Java.use('android.os.SystemProperties');

    var BufferedReader = Java.use('java.io.BufferedReader');

    var ProcessBuilder = Java.use('java.lang.ProcessBuilder');

    var StringBuffer = Java.use('java.lang.StringBuffer');

    var loaded_classes = Java.enumerateLoadedClassesSync();

    send("Loaded " + loaded_classes.length + " classes!");

    var useKeyInfo = false;

    var useProcessManager = false;

    send("loaded: " + loaded_classes.indexOf('java.lang.ProcessManager'));

    if (loaded_classes.indexOf('java.lang.ProcessManager') != -1) {
        try {
            //useProcessManager = true;
            //var ProcessManager = Java.use('java.lang.ProcessManager');
        } catch (err) {
            send("ProcessManager Hook failed: " + err);
        }
    } else {
        send("ProcessManager hook not loaded");
    }

    var KeyInfo = null;

    if (loaded_classes.indexOf('android.security.keystore.KeyInfo') != -1) {
        try {
            //useKeyInfo = true;
            //var KeyInfo = Java.use('android.security.keystore.KeyInfo');
        } catch (err) {
            send("KeyInfo Hook failed: " + err);
        }
    } else {
        send("KeyInfo hook not loaded");
    }

    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pname, flags) {
        var shouldFakePackage = (RootPackages.indexOf(pname) > -1);
        if (shouldFakePackage) {
            send("Bypass root check for package: " + pname);
            pname = "set.package.name.to.a.fake.one.so.we.can.bypass.it";
        }
        return this.getPackageInfo.overload('java.lang.String', 'int').call(this, pname, flags);
    };

    NativeFile.exists.implementation = function() {
        var name = NativeFile.getName.call(this);
        var shouldFakeReturn = (RootBinaries.indexOf(name) > -1);
        if (shouldFakeReturn) {
            send("Bypass return value for binary: " + name);
            return false;
        } else {
            return this.exists.call(this);
        }
    };

    var exec = Runtime.exec.overload('[Ljava.lang.String;');
    var exec1 = Runtime.exec.overload('java.lang.String');
    var exec2 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;');
    var exec3 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;');
    var exec4 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File');
    var exec5 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File');

    exec5.implementation = function(cmd, env, dir) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec5.call(this, cmd, env, dir);
    };

    exec4.implementation = function(cmdarr, env, file) {
        for (var i = 0; i < cmdarr.length; i = i + 1) {
            var tmp_cmd = cmdarr[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }

            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }
        }
        return exec4.call(this, cmdarr, env, file);
    };

    exec3.implementation = function(cmdarr, envp) {
        for (var i = 0; i < cmdarr.length; i = i + 1) {
            var tmp_cmd = cmdarr[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }

            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }
        }
        return exec3.call(this, cmdarr, envp);
    };

    exec2.implementation = function(cmd, env) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec2.call(this, cmd, env);
    };

    exec.implementation = function(cmd) {
        for (var i = 0; i < cmd.length; i = i + 1) {
            var tmp_cmd = cmd[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }

            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
        }

        return exec.call(this, cmd);
    };

    exec1.implementation = function(cmd) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec1.call(this, cmd);
    };

    String.contains.implementation = function(name) {
        if (name == "test-keys") {
            send("Bypass test-keys check");
            return false;
        }
        return this.contains.call(this, name);
    };

    var get = SystemProperties.get.overload('java.lang.String');

    get.implementation = function(name) {
        if (RootPropertiesKeys.indexOf(name) != -1) {
            send("Bypass " + name);
            return RootProperties[name];
        }
        return this.get.call(this, name);
    };

    Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
        onEnter: function(args) {
            var path = Memory.readCString(args[0]);
            path = path.split("/");
            var executable = path[path.length - 1];
            var shouldFakeReturn = (RootBinaries.indexOf(executable) > -1)
            if (shouldFakeReturn) {
                Memory.writeUtf8String(args[0], "/notexists");
                send("Bypass native fopen");
            }
        },
        onLeave: function(retval) {

        }
    });

    Interceptor.attach(Module.findExportByName("libc.so", "system"), {
        onEnter: function(args) {
            var cmd = Memory.readCString(args[0]);
            send("SYSTEM CMD: " + cmd);
            if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id") {
                send("Bypass native system: " + cmd);
                Memory.writeUtf8String(args[0], "grep");
            }
            if (cmd == "su") {
                send("Bypass native system: " + cmd);
                Memory.writeUtf8String(args[0], "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled");
            }
        },
        onLeave: function(retval) {

        }
    });

    /*

    TO IMPLEMENT:

    Exec Family

    int execl(const char *path, const char *arg0, ..., const char *argn, (char *)0);
    int execle(const char *path, const char *arg0, ..., const char *argn, (char *)0, char *const envp[]);
    int execlp(const char *file, const char *arg0, ..., const char *argn, (char *)0);
    int execlpe(const char *file, const char *arg0, ..., const char *argn, (char *)0, char *const envp[]);
    int execv(const char *path, char *const argv[]);
    int execve(const char *path, char *const argv[], char *const envp[]);
    int execvp(const char *file, char *const argv[]);
    int execvpe(const char *file, char *const argv[], char *const envp[]);

    */


    BufferedReader.readLine.overload('boolean').implementation = function() {
        var text = this.readLine.overload('boolean').call(this);
        if (text === null) {
            // just pass , i know it's ugly as hell but test != null won't work :(
        } else {
            var shouldFakeRead = (text.indexOf("ro.build.tags=test-keys") > -1);
            if (shouldFakeRead) {
                send("Bypass build.prop file read");
                text = text.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
            }
        }
        return text;
    };

    var executeCommand = ProcessBuilder.command.overload('java.util.List');

    ProcessBuilder.start.implementation = function() {
        var cmd = this.command.call(this);
        var shouldModifyCommand = false;
        for (var i = 0; i < cmd.size(); i = i + 1) {
            var tmp_cmd = cmd.get(i).toString();
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd.indexOf("mount") != -1 || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd.indexOf("id") != -1) {
                shouldModifyCommand = true;
            }
        }
        if (shouldModifyCommand) {
            send("Bypass ProcessBuilder " + cmd);
            this.command.call(this, ["grep"]);
            return this.start.call(this);
        }
        if (cmd.indexOf("su") != -1) {
            send("Bypass ProcessBuilder " + cmd);
            this.command.call(this, ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"]);
            return this.start.call(this);
        }

        return this.start.call(this);
    };

    if (useProcessManager) {
        var ProcManExec = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File', 'boolean');
        var ProcManExecVariant = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.lang.String', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'boolean');

        ProcManExec.implementation = function(cmd, env, workdir, redirectstderr) {
            var fake_cmd = cmd;
            for (var i = 0; i < cmd.length; i = i + 1) {
                var tmp_cmd = cmd[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                    var fake_cmd = ["grep"];
                    send("Bypass " + cmdarr + " command");
                }

                if (tmp_cmd == "su") {
                    var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
                    send("Bypass " + cmdarr + " command");
                }
            }
            return ProcManExec.call(this, fake_cmd, env, workdir, redirectstderr);
        };

        ProcManExecVariant.implementation = function(cmd, env, directory, stdin, stdout, stderr, redirect) {
            var fake_cmd = cmd;
            for (var i = 0; i < cmd.length; i = i + 1) {
                var tmp_cmd = cmd[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                    var fake_cmd = ["grep"];
                    send("Bypass " + cmdarr + " command");
                }

                if (tmp_cmd == "su") {
                    var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
                    send("Bypass " + cmdarr + " command");
                }
            }
            return ProcManExecVariant.call(this, fake_cmd, env, directory, stdin, stdout, stderr, redirect);
        };
    }

    if (useKeyInfo) {
        KeyInfo.isInsideSecureHardware.implementation = function() {
            send("Bypass isInsideSecureHardware");
            return true;
        }
    }

});""",
            "Android_ReactNative_root_bypass": """/**
        Root detection bypass script for Gantix JailMoney
        https://github.com/GantMan/jail-monkey
        **/
        Java.perform(() => {
            const klass = Java.use("com.gantix.JailMonkey.JailMonkeyModule");
            const hashmap_klass = Java.use("java.util.HashMap");
            const false_obj = Java.use("java.lang.Boolean").FALSE.value;

            klass.getConstants.implementation = function () {
                var h = hashmap_klass.$new();
                h.put("isJailBroken", false_obj);
                h.put("hookDetected", false_obj);
                h.put("canMockLocation", false_obj);
                h.put("isOnExternalStorage", false_obj);
                h.put("AdbEnabled", false_obj);
                return h;
            };
        });""",
            "Android_SSLpinning_bypass": """/************************************************************************
         * Name: SSL Pinning Multiple Libraries Bypass 
         * OS: Android
         * Authors: Maurizio Siddu
         * Source: https://github.com/akabe1/my-FRIDA-scripts
         *************************************************************************/

        setTimeout(function () {
            Java.perform(function () {
                send('');
                send('======');
                send('[#] Android Bypass for various Certificate Pinning methods [#]');
                send('======');


                var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
                var SSLContext = Java.use('javax.net.ssl.SSLContext');


                // TrustManager (Android < 7)
                var TrustManager = Java.registerClass({
                    // Implement a custom TrustManager
                    name: 'dev.asd.test.TrustManager',
                    implements: [X509TrustManager],
                    methods: {
                        checkClientTrusted: function (chain, authType) {},
                        checkServerTrusted: function (chain, authType) {},
                        getAcceptedIssuers: function () {
                            return [];
                        }
                    }
                });

                // Prepare the TrustManager array to pass to SSLContext.init()
                var TrustManagers = [TrustManager.$new()];
                // Get a handle on the init() on the SSLContext class
                var SSLContext_init = SSLContext.init.overload(
                    '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
                try {
                    // Override the init method, specifying the custom TrustManager
                    SSLContext_init.implementation = function (keyManager, trustManager, secureRandom) {
                        send('[+] Bypassing Trustmanager (Android < 7) request');
                        SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
                    };

                } catch (err) {
                    send('[-] TrustManager (Android < 7) pinner not found');
                    //send(err);
                }



                // OkHTTPv3 (double bypass)
                try {
                    var okhttp3_Activity = Java.use('okhttp3.CertificatePinner');
                    okhttp3_Activity.check.overload('java.lang.String', 'java.util.List').implementation = function (str) {
                        send('[+] Bypassing OkHTTPv3 {1}: ' + str);
                        // return true;
                    };
                    // This method of CertificatePinner.check could be found in some old Android app
                    okhttp3_Activity.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (str) {
                        send('[+] Bypassing OkHTTPv3 {2}: ' + str);
                        return true;
                    };

                } catch (err) {
                    send('[-] OkHTTPv3 pinner not found');
                    send(err);
                }



                // Trustkit (triple bypass)
                try {
                    var trustkit_Activity = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
                    trustkit_Activity.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (str) {
                        send('[+] Bypassing Trustkit {1}: ' + str);
                        return true;
                    };
                    trustkit_Activity.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (str) {
                        send('[+] Bypassing Trustkit {2}: ' + str);
                        return true;
                    };
                    var trustkit_PinningTrustManager = Java.use('com.datatheorem.android.trustkit.pinning.PinningTrustManager');
                    trustkit_PinningTrustManager.checkServerTrusted.implementation = function () {
                        send('[+] Bypassing Trustkit {3}');
                    };

                } catch (err) {
                    send('[-] Trustkit pinner not found');
                    //send(err);
                }



                // TrustManagerImpl (Android > 7)
                try {
                    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
                    TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                        send('[+] Bypassing TrustManagerImpl (Android > 7): ' + host);
                        return untrustedChain;
                    };

                } catch (err) {
                    send('[-] TrustManagerImpl (Android > 7) pinner not found');
                    //send(err);
                }



                // Appcelerator Titanium
                try {
                    var appcelerator_PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
                    appcelerator_PinningTrustManager.checkServerTrusted.implementation = function () {
                        send('[+] Bypassing Appcelerator PinningTrustManager');
                    };

                } catch (err) {
                    send('[-] Appcelerator PinningTrustManager pinner not found');
                    //send(err);
                }



                // OpenSSLSocketImpl Conscrypt
                try {
                    var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
                    OpenSSLSocketImpl.verifyCertificateChain.implementation = function (certRefs, JavaObject, authMethod) {
                        send('[+] Bypassing OpenSSLSocketImpl Conscrypt');
                    };

                } catch (err) {
                    send('[-] OpenSSLSocketImpl Conscrypt pinner not found');
                    //send(err);        
                }


                // OpenSSLEngineSocketImpl Conscrypt
                try {
                    var OpenSSLEngineSocketImpl_Activity = Java.use('com.android.org.conscrypt.OpenSSLEngineSocketImpl');
                    OpenSSLSocketImpl_Activity.verifyCertificateChain.overload('[Ljava.lang.Long;', 'java.lang.String').implementation = function (str1, str2) {
                        send('[+] Bypassing OpenSSLEngineSocketImpl Conscrypt: ' + str2);
                    };

                } catch (err) {
                    send('[-] OpenSSLEngineSocketImpl Conscrypt pinner not found');
                    //send(err);
                }



                // OpenSSLSocketImpl Apache Harmony
                try {
                    var OpenSSLSocketImpl_Harmony = Java.use('org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl');
                    OpenSSLSocketImpl_Harmony.verifyCertificateChain.implementation = function (asn1DerEncodedCertificateChain, authMethod) {
                        send('[+] Bypassing OpenSSLSocketImpl Apache Harmony');
                    };

                } catch (err) {
                    send('[-] OpenSSLSocketImpl Apache Harmony pinner not found');
                    //send(err);      
                }



                // PhoneGap sslCertificateChecker (https://github.com/EddyVerbruggen/SSLCertificateChecker-PhoneGap-Plugin)
                try {
                    var phonegap_Activity = Java.use('nl.xservices.plugins.sslCertificateChecker');
                    phonegap_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function (str) {
                        send('[+] Bypassing PhoneGap sslCertificateChecker: ' + str);
                        return true;
                    };

                } catch (err) {
                    send('[-] PhoneGap sslCertificateChecker pinner not found');
                    //send(err);
                }



                // IBM MobileFirst pinTrustedCertificatePublicKey (double bypass)
                try {
                    var WLClient_Activity = Java.use('com.worklight.wlclient.api.WLClient');
                    WLClient_Activity.getInstance().pinTrustedCertificatePublicKey.overload('java.lang.String').implementation = function (cert) {
                        send('[+] Bypassing IBM MobileFirst pinTrustedCertificatePublicKey {1}: ' + cert);
                        return;
                    };
                    WLClient_Activity.getInstance().pinTrustedCertificatePublicKey.overload('[Ljava.lang.String;').implementation = function (cert) {
                        send('[+] Bypassing IBM MobileFirst pinTrustedCertificatePublicKey {2}: ' + cert);
                        return;
                    };

                } catch (err) {
                    send('[-] IBM MobileFirst pinTrustedCertificatePublicKey pinner not found');
                    //send(err);
                }



                // IBM WorkLight (ancestor of MobileFirst) HostNameVerifierWithCertificatePinning (quadruple bypass)
                try {
                    var worklight_Activity = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
                    worklight_Activity.verify.overload('java.lang.String', 'javax.net.ssl.SSLSocket').implementation = function (str) {
                        send('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {1}: ' + str);
                        return;
                    };
                    worklight_Activity.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (str) {
                        send('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {2}: ' + str);
                        return;
                    };
                    worklight_Activity.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;').implementation = function (str) {
                        send('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {3}: ' + str);
                        return;
                    };
                    worklight_Activity.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (str) {
                        send('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {4}: ' + str);
                        return true;
                    };

                } catch (err) {
                    send('[-] IBM WorkLight HostNameVerifierWithCertificatePinning pinner not found');
                    //send(err);
                }



                // Conscrypt CertPinManager
                try {
                    var conscrypt_CertPinManager_Activity = Java.use('com.android.org.conscrypt.CertPinManager');
                    conscrypt_CertPinManager_Activity.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function (str) {
                        send('[+] Bypassing Conscrypt CertPinManager: ' + str);
                        return true;
                    };

                } catch (err) {
                    send('[-] Conscrypt CertPinManager pinner not found');
                    //send(err);
                }



                // CWAC-Netsecurity (unofficial back-port pinner for Android < 4.2) CertPinManager
                try {
                    var cwac_CertPinManager_Activity = Java.use('com.commonsware.cwac.netsecurity.conscrypt.CertPinManager');
                    cwac_CertPinManager_Activity.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function (str) {
                        send('[+] Bypassing CWAC-Netsecurity CertPinManager: ' + str);
                        return true;
                    };

                } catch (err) {
                    send('[-] CWAC-Netsecurity CertPinManager pinner not found');
                    //send(err);
                }



                // Worklight Androidgap WLCertificatePinningPlugin
                try {
                    var androidgap_WLCertificatePinningPlugin_Activity = Java.use('com.worklight.androidgap.plugin.WLCertificatePinningPlugin');
                    androidgap_WLCertificatePinningPlugin_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function (str) {
                        send('[+] Bypassing Worklight Androidgap WLCertificatePinningPlugin: ' + str);
                        return true;
                    };

                } catch (err) {
                    send('[-] Worklight Androidgap WLCertificatePinningPlugin pinner not found');
                    //send(err);
                }



                // Netty FingerprintTrustManagerFactory
                try {
                    var netty_FingerprintTrustManagerFactory = Java.use('io.netty.handler.ssl.util.FingerprintTrustManagerFactory');
                    //NOTE: sometimes this below implementation could be useful 
                    //var netty_FingerprintTrustManagerFactory = Java.use('org.jboss.netty.handler.ssl.util.FingerprintTrustManagerFactory');
                    netty_FingerprintTrustManagerFactory.checkTrusted.implementation = function (type, chain) {
                        send('[+] Bypassing Netty FingerprintTrustManagerFactory');
                    };

                } catch (err) {
                    send('[-] Netty FingerprintTrustManagerFactory pinner not found');
                    //send(err);
                }



                // Squareup CertificatePinner [OkHTTP < v3] (double bypass)
                try {
                    var Squareup_CertificatePinner_Activity = Java.use('com.squareup.okhttp.CertificatePinner');
                    Squareup_CertificatePinner_Activity.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (str1, str2) {
                        send('[+] Bypassing Squareup CertificatePinner {1}: ' + str1);
                        return;
                    };

                    Squareup_CertificatePinner_Activity.check.overload('java.lang.String', 'java.util.List').implementation = function (str1, str2) {
                        send('[+] Bypassing Squareup CertificatePinner {2}: ' + str1);
                        return;
                    };

                } catch (err) {
                    send('[-] Squareup CertificatePinner pinner not found');
                    //send(err);
                }



                // Squareup OkHostnameVerifier [OkHTTP v3] (double bypass)
                try {
                    var Squareup_OkHostnameVerifier_Activity = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
                    Squareup_OkHostnameVerifier_Activity.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (str1, str2) {
                        send('[+] Bypassing Squareup OkHostnameVerifier {1}: ' + str1);
                        return true;
                    };

                    Squareup_OkHostnameVerifier_Activity.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (str1, str2) {
                        send('[+] Bypassing Squareup OkHostnameVerifier {2}: ' + str1);
                        return true;
                    };

                } catch (err) {
                    send('[-] Squareup OkHostnameVerifier pinner not found');
                    //send(err);
                }



                // Android WebViewClient
                try {
                    var AndroidWebViewClient_Activity = Java.use('android.webkit.WebViewClient');
                    AndroidWebViewClient_Activity.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function (obj1, obj2, obj3) {
                        send('[+] Bypassing Android WebViewClient');
                    };

                } catch (err) {
                    send('[-] Android WebViewClient pinner not found');
                    //send(err);
                }



                // Apache Cordova WebViewClient
                try {
                    var CordovaWebViewClient_Activity = Java.use('org.apache.cordova.CordovaWebViewClient');
                    CordovaWebViewClient_Activity.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function (obj1, obj2, obj3) {
                        send('[+] Bypassing Apache Cordova WebViewClient');
                        obj3.proceed();
                    };

                } catch (err) {
                    send('[-] Apache Cordova WebViewClient pinner not found');
                    //send(err):
                }



                // Boye AbstractVerifier
                try {
                    var boye_AbstractVerifier = Java.use('ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier');
                    boye_AbstractVerifier.verify.implementation = function (host, ssl) {
                        send('[+] Bypassing Boye AbstractVerifier: ' + host);
                    };

                } catch (err) {
                    send('[-] Boye AbstractVerifier pinner not found');
                    //send(err):
                }


            });

        }, 0);



































        /* 
           Android SSL Re-pinning frida script v0.2 030417-pier 

           $ adb push burpca-cert-der.crt /data/local/tmp/cert-der.crt
           $ frida -U -f it.app.mobile -l frida-android-repinning.js --no-pause

           https://techblog.mediaservice.net/2017/07/universal-android-ssl-pinning-bypass-with-frida/

           UPDATE 20191605: Fixed undeclared var. Thanks to @oleavr and @ehsanpc9999 !
        */

        """,
            "Android_debugger_check_bypass": """Java.perform(function () {
                // send("[Debugger Check Bypass]  Activated");
                var Debug = Java.use('android.os.Debug');
                Debug.isDebuggerConnected.implementation = function () {
                    send('[Debugger Check Bypass] isDebuggerConnected() bypassed');
                    return false;
                }
        });
        """,
            "Android_fingerprint_bypass": r"""
        Java.perform(function () {
            //Call in try catch as Biometric prompt is supported since api 28 (Android 9)
            try { hookBiometricPrompt_authenticate(); }
            catch (error) { console.log("hookBiometricPrompt_authenticate not supported on this android version") }
            try { hookBiometricPrompt_authenticate2(); }
            catch (error) { console.log("hookBiometricPrompt_authenticate not supported on this android version") }
            try { hookFingerprintManagerCompat_authenticate(); }
            catch (error) { console.log("hookFingerprintManagerCompat_authenticate failed"); }
            try { hookFingerprintManager_authenticate(); }
            catch (error) { console.log("hookFingerprintManager_authenticate failed"); }
        });


        var cipherList = [];
        var StringCls = null;
        Java.perform(function () {
            StringCls = Java.use('java.lang.String');


        });

        function getArgsTypes(overloads) {
        	// there should be just one overload for the constructor
        	// overloads.len == 1 check
            var results = []
        	var i,j;
            for (i in overloads) {
        		console.log('[*] Overload number ind: '+i);
                //if (overloads[i].hasOwnProperty('argumentTypes')) {
                   var parameters = []
                   for (j in overloads[i].argumentTypes) {
                       parameters.push("'" + overloads[i].argumentTypes[j].className + "'")
                   }
               // }
                results.push('(' + parameters.join(', ') + ');')
            }
            return results.join('\n')
        }

        function getAuthResult(resultObj, cryptoInst) {
        	//var clax = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
        	var clax = resultObj;
        	var resu = getArgsTypes(clax['$init'].overloads);
        	//console.log(resu);
        	resu = resu.replace(/\'android\.hardware\.biometrics\.BiometricPrompt\$CryptoObject\'/, 'cryptoInst');
        	resu = resu.replace(/\'android\.hardware\.fingerprint\.FingerprintManager\$CryptoObject\'/, 'cryptoInst');
        	resu = resu.replace('\'int\'', '0');
        	resu = resu.replace('\'boolean\'', 'false');
        	resu = resu.replace(/'.*'/, 'null');
        	//console.log(resu);
        	resu = "resultObj.$new"+resu;
        	var authenticationResultInst = eval(resu);
            console.log("cryptoInst:, " + cryptoInst + " class: " + cryptoInst.$className);
            return authenticationResultInst;
        }

        function getBiometricPromptAuthResult() {
            var sweet_cipher = null;
            var cryptoObj = Java.use('android.hardware.biometrics.BiometricPrompt$CryptoObject');
            var cryptoInst = cryptoObj.$new(sweet_cipher);
            var authenticationResultObj = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
            var authenticationResultInst = getAuthResult(authenticationResultObj, cryptoInst);
            return authenticationResultInst
        }

        function hookBiometricPrompt_authenticate() {
            var biometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt')['authenticate'].overload('android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
            console.log("Hooking BiometricPrompt.authenticate()...");
            biometricPrompt.implementation = function (cancellationSignal, executor, callback) {
                console.log("[BiometricPrompt.BiometricPrompt()]: cancellationSignal: " + cancellationSignal + ", executor: " + ", callback: " + callback);
                var authenticationResultInst = getBiometricPromptAuthResult();
                callback.onAuthenticationSucceeded(authenticationResultInst);
            	console.log("[BiometricPrompt.BiometricPrompt()]: callback.onAuthenticationSucceeded(NULL) called!");
            }
        }

        function hookBiometricPrompt_authenticate2() {
            var biometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt')['authenticate'].overload('android.hardware.biometrics.BiometricPrompt$CryptoObject', 'android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
            console.log("Hooking BiometricPrompt.authenticate2()...");
            biometricPrompt.implementation = function (crypto, cancellationSignal, executor, callback) {
                console.log("[BiometricPrompt.BiometricPrompt2()]: crypto:" + crypto + ", cancellationSignal: " + cancellationSignal + ", executor: " + ", callback: " + callback);
                var authenticationResultInst = getBiometricPromptAuthResult();
                callback.onAuthenticationSucceeded(authenticationResultInst);
            }
        }

        function hookFingerprintManagerCompat_authenticate() {
            /*
            void authenticate (FingerprintManagerCompat.CryptoObject crypto, 
                            int flags, 
                            CancellationSignal cancel, 
                            FingerprintManagerCompat.AuthenticationCallback callback, 
                            Handler handler)
            */
            var fingerprintManagerCompat = null;
            var cryptoObj = null;
            var authenticationResultObj = null;
            try {
                fingerprintManagerCompat = Java.use('android.support.v4.hardware.fingerprint.FingerprintManagerCompat');
                cryptoObj = Java.use('android.support.v4.hardware.fingerprint.FingerprintManagerCompat$CryptoObject');
                authenticationResultObj = Java.use('android.support.v4.hardware.fingerprint.FingerprintManagerCompat$AuthenticationResult');
            } catch (error) {
                try {
                    fingerprintManagerCompat = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat');
                    cryptoObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat$CryptoObject');
                    authenticationResultObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat$AuthenticationResult');
                }
                catch (error) {
                    console.log("FingerprintManagerCompat class not found!");
                    return
                }
            }
            console.log("Hooking FingerprintManagerCompat.authenticate()...");
            var fingerprintManagerCompat_authenticate = fingerprintManagerCompat['authenticate'];
            fingerprintManagerCompat_authenticate.implementation = function (crypto, flags, cancel, callback, handler) {
                console.log("[FingerprintManagerCompat.authenticate()]: crypto: " + crypto + ", flags: " + flags + ", cancel:" + cancel + ", callback: " + callback + ", handler: " + handler);
                //console.log(enumMethods(callback.$className));
                callback['onAuthenticationFailed'].implementation = function () {
                    console.log("[onAuthenticationFailed()]:");
                    var sweet_cipher = null;
                    var cryptoInst = cryptoObj.$new(sweet_cipher);
                    var authenticationResultInst = getAuthResult(authenticationResultObj, cryptoInst);
                    callback.onAuthenticationSucceeded(authenticationResultInst);
                }
                return this.authenticate(crypto, flags, cancel, callback, handler);
            }
        }

        function hookFingerprintManager_authenticate() {
            /*
            public void authenticate (FingerprintManager.CryptoObject crypto, 
                            CancellationSignal cancel, 
                            int flags, 
                            FingerprintManager.AuthenticationCallback callback, 
                            Handler handler)
        Error: authenticate(): has more than one overload, use .overload(<signature>) to choose from:
            .overload('android.hardware.fingerprint.FingerprintManager$CryptoObject', 'android.os.CancellationSignal', 'int', 'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback', 'android.os.Handler')
            .overload('android.hardware.fingerprint.FingerprintManager$CryptoObject', 'android.os.CancellationSignal', 'int', 'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback', 'android.os.Handler', 'int')
            */
            var fingerprintManager = null;
            var cryptoObj = null;
            var authenticationResultObj = null;
            try {
                fingerprintManager = Java.use('android.hardware.fingerprint.FingerprintManager');
                cryptoObj = Java.use('android.hardware.fingerprint.FingerprintManager$CryptoObject');
                authenticationResultObj = Java.use('android.hardware.fingerprint.FingerprintManager$AuthenticationResult');
            } catch (error) {
                try {
                    fingerprintManager = Java.use('androidx.core.hardware.fingerprint.FingerprintManager');
                    cryptoObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManager$CryptoObject');
                    authenticationResultObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManager$AuthenticationResult');
                }
                catch (error) {
                    console.log("FingerprintManager class not found!");
                    return
                }
            }
            console.log("Hooking FingerprintManager.authenticate()...");



            var fingerprintManager_authenticate = fingerprintManager['authenticate'].overload('android.hardware.fingerprint.FingerprintManager$CryptoObject', 'android.os.CancellationSignal', 'int', 'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback', 'android.os.Handler');
            fingerprintManager_authenticate.implementation = function (crypto, cancel, flags, callback, handler) {
                console.log("[FingerprintManager.authenticate()]: crypto: " + crypto + ", flags: " + flags + ", cancel:" + cancel + ", callback: " + callback + ", handler: " + handler);
                var sweet_cipher = null;
                var cryptoInst = cryptoObj.$new(sweet_cipher);
                var authenticationResultInst = getAuthResult(authenticationResultObj, cryptoInst);
                callback.onAuthenticationSucceeded(authenticationResultInst);
                return this.authenticate(crypto, cancel, flags, callback, handler);
            }
        }


        function enumMethods(targetClass) {
            var hook = Java.use(targetClass);
            var ownMethods = hook.class.getDeclaredMethods();

            return ownMethods;
        }

        """,
            "Android_deepLink_observer": """Java.perform(function() {
    var Intent = Java.use("android.content.Intent");
    Intent.getData.implementation = function() {
        var action = this.getAction() !== null ? this.getAction().toString() : false;
        if (action) {
            console.log("[*] Intent.getData() was called");
            console.log("[*] Activity: " + this.getComponent().getClassName());
            console.log("[*] Action: " + action);
            var uri = this.getData();
            if (uri !== null) {
                console.log("\n[*] Data");
                uri.getScheme() && console.log("- Scheme:\t" + uri.getScheme() + "://");
                uri.getHost() && console.log("- Host:\t\t/" + uri.getHost());
                uri.getQuery() && console.log("- Params:\t" + uri.getQuery());
                uri.getFragment() && console.log("- Fragment:\t" + uri.getFragment());
                console.log("\n\n");
            } else {
                console.log("[-] No data supplied.");
            }
        }
        return this.getData();
    }
});""",
            "Android_Log_class_Watcher":"""
            Java.perform(function () {var Log = Java.use('android.util.Log');
['d', 'e', 'i', 'v', 'w'].forEach(function(level) {
    Log[level].overload('java.lang.String', 'java.lang.String').implementation = function(tag, msg) {
        var logMessage = tag + ': ' + msg;
        send({LoggedMessage: logMessage });
        return this[level](tag, msg);
    };
});
            });"""
        }

        # configure window
        self.title("Auto Frida Tool - All rights reserved to Maor Cohen")
        self.geometry(f"{1400}x{730}")

        # configure grid layout (4x4)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure((2, 3), weight=0)
        self.grid_rowconfigure((0, 1, 2), weight=1)

        # create sidebar frame with widgets
        # sidebar frame settings
        self.sidebar_frame = customtkinter.CTkFrame(self, width=140, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew")

        # sidebar logo
        self.logo_label = customtkinter.CTkLabel(self.sidebar_frame, text="Auto Frida Tool",
                                                 font=customtkinter.CTkFont(size=20))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        # sidebar buttons
        self.appActions_label = customtkinter.CTkLabel(self.sidebar_frame, text="App Actions",
                                                       font=customtkinter.CTkFont(size=15))
        self.appActions_label.grid(row=1, column=0, padx=20, pady=(5, 5))
        self.sidebar_spawn_button = customtkinter.CTkButton(self.sidebar_frame, text="Spawn App",
                                                            command=self.sidebar_button_spawn_clicked)
        self.sidebar_spawn_button.grid(row=2, column=0, padx=20, pady=(0, 5))
        self.sidebar_attach_button = customtkinter.CTkButton(self.sidebar_frame, text="Attach App",
                                                             command=self.sidebar_button_attach_clicked)
        self.sidebar_attach_button.grid(row=3, column=0, padx=20, pady=(0, 15))
        self.GUIactions_label = customtkinter.CTkLabel(self.sidebar_frame, text="GUI Actions",
                                                       font=customtkinter.CTkFont(size=15))
        self.GUIactions_label.grid(row=4, column=0, padx=20, pady=(5, 5))
        self.sidebar_clear_button = customtkinter.CTkButton(self.sidebar_frame, text="Clear Console",
                                                            command=self.sidebar_button_clear_console_clicked)
        self.sidebar_clear_button.grid(row=5, column=0, padx=20, pady=(0, 5))
        self.sidebar_restart_button = customtkinter.CTkButton(self.sidebar_frame, text="Restart AutoFrida",
                                                              command=self.sidebar_button_Restart_clicked)
        self.sidebar_restart_button.grid(row=6, column=0, padx=20, pady=(0, 5))
        self.sidebar_reconnect_device_button = customtkinter.CTkButton(self.sidebar_frame, text="Reconnect Device",
                                                                       command=self.sidebar_button_reconnect_device_clicked)
        self.sidebar_reconnect_device_button.grid(row=7, column=0, padx=20, pady=(0, 5))

        # sidebar modes
        self.settings_label = customtkinter.CTkLabel(self.sidebar_frame, text="Project",
                                                     font=customtkinter.CTkFont(size=15))
        self.settings_label.grid(row=8, column=0, padx=20, pady=(20, 5))

        self.sidebar_spawn_button = customtkinter.CTkButton(self.sidebar_frame, text="Save Project",
                                                            command=self.sidebar_button_save_project_clicked)
        self.sidebar_spawn_button.grid(row=9, column=0, padx=20, pady=(0, 5))
        self.sidebar_spawn_button = customtkinter.CTkButton(self.sidebar_frame, text="Load Project",
                                                            command=self.sidebar_button_load_project_clicked)
        self.sidebar_spawn_button.grid(row=10, column=0, padx=20, pady=(0, 5))

        self.appearance_mode_label = customtkinter.CTkLabel(self.sidebar_frame, text="Appearance & Scale", anchor="w",
                                                            font=customtkinter.CTkFont(size=15))
        self.appearance_mode_label.grid(row=50, column=0, padx=20, pady=(20, 5))

        self.appearance_mode_optionemenu = customtkinter.CTkOptionMenu(self.sidebar_frame,
                                                                       values=["Light", "Dark", "System"],
                                                                       command=self.change_appearance_mode_event)
        self.appearance_mode_optionemenu.grid(row=51, column=0, padx=20, pady=(5, 0))

        self.scaling_optionemenu = customtkinter.CTkOptionMenu(self.sidebar_frame,
                                                               values=["70%", "80%", "90%", "100%", "110%", "120%",
                                                                       "130%"], command=self.change_scaling_event)
        self.scaling_optionemenu.grid(row=52, column=0, padx=20, pady=(5, 0))

        # create main app_name_entry and button
        self.app_name_entry = customtkinter.CTkEntry(self, placeholder_text="Insert App Name Here, Case sensitive!",
                                                     font=("consolas", 15), width=20)
        self.app_name_entry.grid(row=3, column=1, columnspan=1, padx=(20, 0), pady=(20, 20), sticky="nsew")

        # create save and update app name buttons
        self.save_app_name_button = customtkinter.CTkButton(master=self, fg_color="transparent", text="Save App Name",
                                                            command=self.save_app_name_button_clicked, border_width=2,
                                                            text_color=("gray10", "#DCE4EE"))
        self.save_app_name_button.grid(row=3, column=2, padx=(20, 20), pady=(10, 10), sticky="ew")
        self.update_app_name_button = customtkinter.CTkButton(master=self, fg_color="transparent",
                                                              text="Update App Name",
                                                              command=self.update_app_name_button_clicked,
                                                              border_width=2, text_color=("gray10", "#DCE4EE"))
        self.update_app_name_button.grid(row=3, column=2, padx=(20, 20), pady=(10, 10), sticky="ew")
        self.update_app_name_button.grid_remove()

        # -------------------------------------------------------------------------
        # -------------------------------------------------------------------------
        # -------------------------------------------------------------------------
        # -------------------------------------------------------------------------
        # -------------------------------------------------------------------------
        # -------------------------------------------------------------------------
        self.consoles_tabview = customtkinter.CTkTabview(self)
        self.consoles_tabview.grid(row=0, column=1, padx=(20, 0), pady=(20, 0), sticky="nsew", rowspan=3, columnspan=1)
        self.consoles_tabview.add("Console")
        self.consoles_tabview.add("File Manager")
        self.consoles_tabview.add("Classes")
        self.consoles_tabview.add("Logs")

        # create console_textbox
        self.logs_textbox = customtkinter.CTkTextbox(self.consoles_tabview.tab("Logs"), state="disabled",
                                                        border_width=2,
                                                        font=("consolas", 15), wrap='none')
        self.logs_textbox.grid(row=0, column=0, padx=(0, 0), pady=(0, 0), sticky="nsew")

        # create console_textbox
        self.console_textbox = customtkinter.CTkTextbox(self.consoles_tabview.tab("Console"), state="disabled",
                                                        border_width=2,
                                                        font=("consolas", 15), wrap='none')
        self.console_textbox.grid(row=0, column=0, padx=(0, 0), pady=(0, 0), sticky="nsew")

        # create files_console_textbox
        self.files_console_textbox = customtkinter.CTkTextbox(self.consoles_tabview.tab("File Manager"),
                                                              state="disabled",
                                                              border_width=2,
                                                              font=("consolas", 15), wrap='none')
        self.files_console_textbox.grid(row=0, column=0, padx=(0, 0), pady=(0, 0), sticky="nsew")

        self.scrollable_files = customtkinter.CTkScrollableFrame(self.consoles_tabview.tab("File Manager"),
                                                                 label_text="Files List")
        self.scrollable_files.grid(row=7, column=0, padx=(5, 5), pady=(5, 5), sticky="nsew")

        # create files_console_textbox
        self.classes_console_textbox = customtkinter.CTkTextbox(self.consoles_tabview.tab("Classes"),
                                                              state="disabled",
                                                              border_width=2,
                                                              font=("consolas", 15), wrap='none')
        self.classes_console_textbox.grid(row=0, column=0, padx=(0, 0), pady=(0, 0), sticky="nsew")




        # Set the fill argument to expand in both directions
        self.consoles_tabview.tab("Console").grid_rowconfigure(0, weight=1)
        self.consoles_tabview.tab("Console").grid_columnconfigure(0, weight=1)
        self.consoles_tabview.tab("File Manager").grid_rowconfigure(0, weight=1)
        self.consoles_tabview.tab("File Manager").grid_columnconfigure(0, weight=1)
        self.consoles_tabview.tab("Classes").grid_rowconfigure(0, weight=1)
        self.consoles_tabview.tab("Classes").grid_columnconfigure(0, weight=1)
        self.consoles_tabview.tab("Logs").grid_rowconfigure(0, weight=1)
        self.consoles_tabview.tab("Logs").grid_columnconfigure(0, weight=1)


        self.print_to_console_textBox(text="Console Output\n", color='green')
        self.print_to_files_console_textbox(text="Files Management Console\n", color='green')
        self.print_to_classes_console_textbox(text="classes Console\n", color='green')
        self.print_to_logs_console_textbox(text="Logs Console\n", color='green')


        # create tabview and menus inside
        self.tabview = customtkinter.CTkTabview(self, width=320)
        self.tabview.grid(row=0, column=2, padx=(20, 20), pady=(20, 0), sticky="nsew")

        # details tab
        self.tabview.add("Details")
        self.details_textbox = customtkinter.CTkTextbox(self.tabview.tab("Details"), wrap='none', width=300,
                                                        font=("consolas", 15), state="disabled", border_width=2)
        self.details_textbox.grid(row=0, column=2, padx=(0, 0), pady=(0, 0), sticky="nsew")


        # add colors
        self.console_textbox.tag_config('red', foreground='#FF0000')
        self.console_textbox.tag_config('green', foreground='#2AFF00')
        self.console_textbox.tag_config('orange', foreground='#FF9700')
        self.console_textbox.tag_config('blue', foreground='#ABB3FF')
        self.details_textbox.tag_config('red', foreground='#FF0000')
        self.details_textbox.tag_config('green', foreground='#2AFF00')
        self.details_textbox.tag_config('blue', foreground='#57E4D1')
        self.files_console_textbox.tag_config('red', foreground='#FF0000')
        self.files_console_textbox.tag_config('green', foreground='#2AFF00')
        self.files_console_textbox.tag_config('orange', foreground='#FF9700')
        self.classes_console_textbox.tag_config('red', foreground='#FF0000')
        self.classes_console_textbox.tag_config('green', foreground='#2AFF00')
        self.classes_console_textbox.tag_config('orange', foreground='#FF9700')
        self.logs_textbox.tag_config('red', foreground='#FF0000')
        self.logs_textbox.tag_config('green', foreground='#2AFF00')
        self.logs_textbox.tag_config('orange', foreground='#FF9700')


        self.tabview.tab("Details").columnconfigure(0, weight=1)
        self.tabview.tab("Details").rowconfigure(0, weight=1)

        self.print_to_details_textBox(text="App details\n", color='green')
        self.tabview.add("DevicePackages")

        self.tabview.add("Analyze")
        # create tabview and menus inside
        self.analyzeTabview = customtkinter.CTkTabview(self.tabview.tab("Analyze"), width=300)
        self.analyzeTabview.grid(row=0, column=0, padx=(0, 0), pady=(5, 0), sticky="nsew")
        self.analyzeTabview.add("Static")
        self.analyzeTabview.add("Dynamic")
        self.analyzeTabview.rowconfigure(0, weight=1)
        self.analyzeTabview.columnconfigure(0, weight=1)

        self.pull_apk_button = customtkinter.CTkButton(self.analyzeTabview.tab("Static"), text="Pull APK file",
                                                       command=self.pull_apk_button_clicked)
        self.pull_apk_button.grid(row=0, column=0, padx=75, pady=(5, 5))

        self.open_apk_button = customtkinter.CTkButton(self.analyzeTabview.tab("Static"), text="Open APK file",
                                                       command=self.open_apk_button_clicked)
        self.open_apk_button.grid(row=1, column=0, padx=75, pady=(0, 5))
        self.open_apk_button.grid_remove()

        self.show_current_activity_button = customtkinter.CTkButton(self.analyzeTabview.tab("Static"), text="Show Current Activity",
                                                      command=self.show_current_activity_button_clicked)
        self.show_current_activity_button.grid(row=2, column=0, padx=75, pady=(0, 5))

        self.tabview.add("Findings")
        self.scrollable_findings = customtkinter.CTkScrollableFrame(self.tabview.tab("Findings"))
        self.scrollable_findings.grid(row=0, column=0, padx=(0, 0), pady=(0, 0), sticky="nsew")

        # Configure the column and row to expand and fill the available space
        self.tabview.tab("Findings").columnconfigure(0, weight=1)
        self.tabview.tab("Findings").rowconfigure(0, weight=1)

        self.export_findings_button = customtkinter.CTkButton(master=self.scrollable_findings, fg_color="transparent",
                                                              text="Export findings (PDF)",
                                                              command=self.export_findings_button_clicked,
                                                              border_width=2, text_color=("gray10", "#DCE4EE"))
        self.export_findings_button.grid(row=0, column=0, padx=70, pady=(10, 10), sticky="nsew")

        self.tabview.tab("DevicePackages").grid_columnconfigure(0, weight=1)  # configure grid of individual tabs

        self.device_packages_menu = customtkinter.CTkOptionMenu(self.tabview.tab("DevicePackages"),
                                                                dynamic_resizing=True, values=[])
        self.device_packages_menu.grid(row=0, column=0, padx=20, pady=(20, 10))
        self.device_packages_menu.set("Apps not loaded")
        self.sidebar_running_apps_button = customtkinter.CTkButton(self.tabview.tab("DevicePackages"),
                                                                   text="Load Running Apps",
                                                                   command=self.load_running_apps_button_clicked)
        self.sidebar_running_apps_button.grid(row=1, column=0, padx=20, pady=10)
        self.sidebar_all_apps_button = customtkinter.CTkButton(self.tabview.tab("DevicePackages"), text="Load All Apps",
                                                               command=self.load_all_apps_button_clicked)
        self.sidebar_all_apps_button.grid(row=2, column=0, padx=20, pady=10)
        self.sidebar_selected_app_button = customtkinter.CTkButton(self.tabview.tab("DevicePackages"),
                                                                   text="Update",
                                                                   command=self.load_selected_app_button_clicked,
                                                                   fg_color='green', hover_color='green'
                                                                   )
        self.sidebar_selected_app_button.grid(row=3, column=0, padx=20, pady=10)

        #
        # # create slider and progressbar frame
        # self.slider_progressbar_frame = customtkinter.CTkFrame(self, fg_color="transparent")
        # self.slider_progressbar_frame.grid(row=2, column=1, padx=(20, 0), pady=(3, 3), sticky="nsew")
        # self.slider_progressbar_frame.grid_columnconfigure(0, weight=1)
        # self.slider_progressbar_frame.grid_rowconfigure(0, weight=1)
        # # # Animated progress bar
        # self.progressbar_1 = customtkinter.CTkProgressBar(self.slider_progressbar_frame)
        # self.progressbar_1.grid(row=1, column=1, padx=(5, 5), pady=(0, 0), sticky="nsew")
        # self.progressbar_1.grid_rowconfigure(0,weight=1)
        # self.progressbar_1.grid_columnconfigure(0,weight=1)
        # self.progressbar_1.configure(mode="indeterminnate",indeterminate_speed=2)
        # self.progressbar_1.start()

        # create scrollable frame
        self.scrollable_frame = customtkinter.CTkScrollableFrame(self, label_text="Scripts Section")
        self.scrollable_frame.grid(row=1, column=2, padx=(20, 20), pady=(20, 0), sticky="nsew")
        self.load_default_bypasses_scripts()

        self.upload_script_button = customtkinter.CTkButton(master=self.scrollable_frame, fg_color="transparent",
                                                            text="Upload New Script",
                                                            command=self.upload_script_button_clicked, border_width=2,
                                                            text_color=("gray10", "#DCE4EE"))
        self.upload_script_button.grid(row=0, column=0, padx=(20, 20), pady=(20, 20), sticky="nsew")

        # Center the switch widget within its parent container's column
        self.scrollable_frame.grid_rowconfigure(self.scriptSwitchRow, weight=1)
        self.scrollable_frame.grid_columnconfigure(0, weight=1)

        # set default scale and apperance mode
        self.appearance_mode_optionemenu.set("Dark")
        self.scaling_optionemenu.set("100%")

    def show_current_activity_button_clicked(self):
        show_command = 'adb shell dumpsys window | find "mCurrentFocus"'
        try:
            result = subprocess.run(show_command, shell=True, check=True, capture_output=True, text=True)
            current_activity = result.stdout.strip().split('/')[-1].replace("}","")
            self.print_to_console_textBox(text=f"Current Activity: {current_activity}",color='blue')
        except subprocess.CalledProcessError as e:
            self.print_to_console_textBox(text=f"Error in show_current_activity_button_clicked: {e}",color='red')


    def create_new_file_opened(self, filename):
        if '/data/user/0/' in filename:
            display_filename = filename.replace('/data/user/0/', '')
        if '/storage/emulated/0/' in filename:
            display_filename = filename.replace('/storage/emulated/0/', '')
        self.la = customtkinter.CTkLabel(self.scrollable_files, text=display_filename,
                                         font=customtkinter.CTkFont(size=15))
        self.la.grid(row=self.scrollable_files_row, column=0, padx=5, pady=(5, 5), sticky="w")
        self.open = customtkinter.CTkButton(self.scrollable_files, text="Print",
                                            command=lambda file=filename: self.print_traget_file_clicked(file))
        self.open.grid(row=self.scrollable_files_row, column=1, padx=5, pady=(5, 5), sticky="w")
        self.dump = customtkinter.CTkButton(self.scrollable_files, text="Dump",
                                            command=lambda file=filename: self.dump_file_from_device_button_clicked(
                                                file))
        self.dump.grid(row=self.scrollable_files_row, column=2, padx=5, pady=(5, 5), sticky="w")
        self.scrollable_files_row += 1

    def dump_file_from_device_thread(self, filename):
        try:
            dump_folder = os.path.join(os.getcwd(), "dumped_files")
            name = filename.split('/')[-1]
            sdcard_path = f'"/sdcard/{name}"'
            pc_path = os.path.join(dump_folder, name)
            if not os.path.exists(dump_folder):
                os.mkdir(dump_folder)
            self.print_to_files_console_textbox(text=f"Dumping '{filename}'")
            copy_command = f"adb shell su -c 'cp {filename} {sdcard_path}'"
            subprocess.run(copy_command, shell=True, check=True)
            pull_command = f'adb pull {sdcard_path} {pc_path}'
            subprocess.run(pull_command, shell=True, check=True)
            if os.path.exists(pc_path):
                self.print_to_files_console_textbox(text=f"Dump success, opening..", color='green')
                self.print_to_files_console_textbox(text=f"Dumped file is in dumped_files folder")
                os.startfile(pc_path)
        except Exception as e:
            self.print_to_files_console_textbox(text=f"Error:dump_file_from_device\n{e}", color='red')

    def dump_file_from_device_button_clicked(self, filename):
        dump_thread = threading.Thread(target=self.dump_file_from_device_thread(filename))
        dump_thread.start()

    def print_traget_file_thread(self, filename):
        try:
            self.print_to_files_console_textbox(text=f"Opening {filename}", color="green")
            command = f'adb shell su -c "cat {filename}"'
            result = subprocess.run(command, capture_output=True, text=True, shell=True)
            file_content = result.stdout.strip()
            self.print_to_files_console_textbox(text=f"File content:", color="green")
            self.print_to_files_console_textbox(text=f"{file_content}")
        except Exception as e:
            self.print_to_files_console_textbox(text=f"Error:print_traget_file_thread\n{e}", color='red')

    def print_traget_file_clicked(self, filename):
        print_thread = threading.Thread(target=self.print_traget_file_thread(filename))
        print_thread.start()

    def open_apk_button_clicked(self):
        try:
            if os.path.exists(frap.apk_pc_path):
                os.startfile(frap.apk_pc_path)
                self.print_to_console_textBox(text=f"APK opened successfully.", color='green')
            else:
                self.print_to_console_textBox(text=f"APK path not exist: {frap.apk_pc_path}", color='orange')
        except Exception as e:
            self.print_to_console_textBox(text=f"Error: {e}", color='red')

    def pull_apk_button_clicked(self):
        pull_thread = threading.Thread(target=frap.pull_apk_file_thread)
        pull_thread.start()

    def add_finding_to_finding_tab(self, name):
        if name not in self.findings:
            self.findings.append(name)
            finding_checkbox = customtkinter.CTkCheckBox(self.scrollable_findings, text=name)
            finding_checkbox.grid(row=self.scrollable_findings_row, column=0, padx=10, pady=(0, 10), sticky="ew")
            self.scrollable_findings_row += 1
            GUIapp.print_to_console_textBox(text=f"[Finding] {name}", color='orange')

    def export_findings_button_clicked(self):
        GUIapp.print_to_console_textBox(text="Export button clicked.")
        # itrate over which checkboxes is on , append his names to list. and generate.
        pass

    def print_to_logs_console_textbox(self, text, color=''):
        self.logs_textbox.configure(state="normal")
        if color != '':
            self.logs_textbox.insert("end", text + "\n", color)
        else:
            self.logs_textbox.insert("end", text + "\n")
        self.logs_textbox.configure(state="disabled")
        self.logs_textbox.yview(tkinter.END)


    def print_to_classes_console_textbox(self, text, color=''):
        self.classes_console_textbox.configure(state="normal")
        if color != '':
            self.classes_console_textbox.insert("end", text + "\n", color)
        else:
            self.classes_console_textbox.insert("end", text + "\n")
        self.classes_console_textbox.configure(state="disabled")
        self.classes_console_textbox.yview(tkinter.END)
    def print_to_files_console_textbox(self, text, color=''):
        self.files_console_textbox.configure(state="normal")
        if color != '':
            self.files_console_textbox.insert("end", text + "\n", color)
        else:
            self.files_console_textbox.insert("end", text + "\n")
        self.files_console_textbox.configure(state="disabled")
        self.files_console_textbox.yview(tkinter.END)

    def print_to_console_textBox(self, text, color=''):
        self.console_textbox.configure(state="normal")
        if color != '':
            self.console_textbox.insert("end", text + "\n", color)
        else:
            self.console_textbox.insert("end", text + "\n")
        self.console_textbox.configure(state="disabled")
        self.console_textbox.yview(tkinter.END)

    def print_to_details_textBox(self, text, color=''):
        if color != '':
            self.details_textbox.configure(state="normal")
            self.details_textbox.insert("end", text + "\n", color)
            self.details_textbox.configure(state="disabled")
        else:
            self.details_textbox.configure(state="normal")
            self.details_textbox.insert("end", text + "\n")
            self.details_textbox.configure(state="disabled")
        # self.console_textbox.yview(tkinter.END)

    def clear_details_tab_textbox(self):
        self.details_textbox.configure(state="normal")
        self.details_textbox.delete("2.0", "end")  # Clear the entire content
        self.details_textbox.insert("end", "\n")
        self.details_textbox.configure(state="disabled")

    def load_default_bypasses_scripts(self):
        script_to_auto_toggle = ['Android_Log_class_Watcher','Android_file_guard']
        for script_name, script_content in self.default_bypasses_scripts.items():
            scriptSwitch = customtkinter.CTkSwitch(master=self.scrollable_frame, text=f"{script_name}")
            scriptSwitch.grid(row=self.scriptSwitchRow, column=0, padx=10, pady=(0, 20))
            if script_name in script_to_auto_toggle:
                scriptSwitch.select()
            self.scriptSwitchRow += 1
            self.scrollable_frame_switches[script_name] = scriptSwitch
            self.scripts[script_name] = script_content
        self.print_to_console_textBox(text=f"Default scripts uploaded.", color='green')

    def change_appearance_mode_event(self, new_appearance_mode: str):
        customtkinter.set_appearance_mode(new_appearance_mode)

    def change_scaling_event(self, new_scaling: str):
        new_scaling_float = int(new_scaling.replace("%", "")) / 100
        customtkinter.set_widget_scaling(new_scaling_float)

    def sidebar_button_spawn_clicked(self):
        spawn_button_thread = threading.Thread(target=frap.spawn_frida)
        spawn_button_thread.start()

    def sidebar_button_attach_clicked(self):
        attach_button_thread = threading.Thread(target=frap.attach_frida)
        attach_button_thread.start()

    def sidebar_button_Restart_clicked(self):
        confirmation = messagebox.askokcancel("Confirmation", "Are you sure you want to restart?")

        if confirmation:
            current_program_exec = sys.executable
            os.execl(current_program_exec, current_program_exec, *sys.argv)
        else:
            pass  # User cancelled restart, do nothing

    def sidebar_button_reconnect_device_clicked(self):
        GUIapp.print_to_console_textBox(text="Looking for device connection.., wait 2 sec after connection",
                                        color='orange')
        frap.device_is_connected = False

    def sidebar_button_clear_console_clicked(self):
        self.console_textbox.configure(state="normal")
        self.console_textbox.delete("2.0", "end")  # Clear the entire content
        self.console_textbox.insert("end", "\n")
        self.console_textbox.configure(state="disabled")

    def load_all_tuggled_scripts(self):
        self.print_to_console_textBox(text=f"Loading all toggled scripts..")
        if self.scrollable_frame_switches:
            for name, switch in self.scrollable_frame_switches.items():
                if switch.get() == 1:
                    if name in self.wanted_scripts:
                        pass
                    else:
                        self.wanted_scripts.append(name)
                elif switch.get() == 0:
                    if name in self.wanted_scripts:
                        self.wanted_scripts.pop(self.wanted_scripts.index(name))
            if not len(self.wanted_scripts) == 0:
                for name in self.wanted_scripts:
                    self.script_to_load += self.scripts[name] + '\n'
        self.print_to_console_textBox(text=f"Loading done.", color='green')

    def save_app_name_button_clicked(self):
        app_name = self.app_name_entry.get()
        if app_name == "":
            self.print_to_console_textBox(f"App name not saved because its empty.", color='orange')
        else:
            if "App Name" in self.app_details_dict:
                if self.app_details_dict["App Name"] != app_name:
                    self.print_to_console_textBox(text=f"App name edited: '{app_name}'", color='green')
                else:
                    self.print_to_console_textBox(text=f"App name saved: '{app_name}'", color='green')
            else:
                self.print_to_console_textBox(text=f"App name saved: '{app_name}'", color='green')
            self.app_details_dict["App Name"] = app_name
            self.clear_details_tab_textbox()
            self.update_details_tab_content()
            self.app_name_entry.configure(state="disabled")
            self.save_app_name_button.configure(state="disabled")
            self.save_app_name_button.grid_remove()
            self.update_app_name_button.grid()

    def update_app_name_button_clicked(self):
        self.app_name_entry.configure(state="normal")
        self.save_app_name_button.grid()
        self.save_app_name_button.configure(state="normal")
        self.update_app_name_button.grid_remove()

    def update_details_tab_content(self):
        self.clear_details_tab_textbox()
        for key, val in self.app_details_dict.items():
            self.print_to_details_textBox(text=f"{key} : {val}", color="blue")

    def upload_script_button_clicked(self):
        file_path = filedialog.askopenfilename(filetypes=[("JavaScript Files", "*.js")])
        if file_path:
            script_name = file_path.split("/")[-1]  # Extract script name from the file path
            if ".js" not in script_name:
                self.print_to_console_textBox(text=f"Upload only .js files, try again.", color='orange')
                return
            with open(file_path, "r") as file:
                if script_name in self.scripts.keys() or script_name.replace(".js", "") in self.scripts.keys():
                    self.print_to_console_textBox(text=f"Script '{script_name}' is already in scripts list.",
                                                  color='orange')
                else:
                    content = file.read()
                    self.scripts[script_name] = content
                    self.print_to_console_textBox(text=f"Script '{script_name}' uploaded and added to the list.",
                                                  color='green')
                    scriptSwitch = customtkinter.CTkSwitch(master=self.scrollable_frame, text=f"{script_name}")
                    scriptSwitch.grid(row=self.scriptSwitchRow, column=0, padx=10, pady=(0, 20))
                    self.scriptSwitchRow += 1
                    self.scrollable_frame_switches[script_name] = scriptSwitch

    def load_all_apps_button_clicked(self):
        load_all_apps_thread = threading.Thread(target=frap.load_all_apps)
        load_all_apps_thread.start()

    def load_running_apps_button_clicked(self):
        load_apps_thread = threading.Thread(target=frap.load_running_apps)
        load_apps_thread.start()

    def load_selected_app_button_clicked(self):
        selected_app = self.device_packages_menu.get()
        if selected_app == 'List updated!' or selected_app == 'No apps found!' or selected_app == "Apps not loaded":
            self.print_to_console_textBox(text=f"No app selected,select from list or insert manually.", color='orange')
            return
        frap.name = self.app_details_dict["App Name"] = selected_app.split("|")[0].strip()
        frap.package_name = self.app_details_dict["Package Name"] = selected_app.split("|")[1].strip()
        self.update_details_tab_content()
        self.print_to_console_textBox(text=f"Loading selected app: {selected_app}")
        self.app_name_entry.configure(state="normal")
        self.app_name_entry.delete(0, "end")
        self.app_name_entry.insert(0, self.app_details_dict["App Name"])
        self.app_name_entry.configure(state="disabled")
        self.save_app_name_button.configure(state="disabled")
        self.save_app_name_button.grid_remove()
        self.update_app_name_button.grid()
        self.print_to_console_textBox(text="Done.", color='green')

    def sidebar_button_save_project_clicked(self):
        try:
            file_path = filedialog.asksaveasfilename(defaultextension=".pkl", filetypes=[("Project Files", "*.pkl")])
            if file_path:
                project_data = {
                    'console_text': self.console_textbox.get("1.0", "end-1c"),
                    'details_text': self.details_textbox.get("1.0", "end-1c"),
                    'files_text': self.files_console_textbox.get("1.0", "end-1c"),
                    'app_details_dict': self.app_details_dict,
                    'findings': self.findings,
                    'files_list': frap.used_files,
                    'scripts_dict': {},
                    'apk_path': frap.apk_device_path,
                    'data_path': frap.data_path,
                    'pc_apk_path': frap.apk_pc_path,
                    'is_apk_pulled': frap.is_apk_pulled
                }
                if "App Name" in self.app_details_dict.keys():
                    project_data["App Name"] = self.app_details_dict["App Name"]

                if self.scripts:
                    for key, val in self.scripts.items():
                        if key not in self.default_bypasses_scripts:
                            project_data['scripts_dict'][key] = val

                with open(file_path, 'wb') as file:
                    pickle.dump(project_data, file)
                self.print_to_console_textBox(text=f"Project saved successfully. in {file_path}", color='green')

        except Exception as e:
            self.print_to_console_textBox(text=f"Error while saving project: {e}", color='red')

    def sidebar_button_load_project_clicked(self):
        try:
            file_path = filedialog.askopenfilename(filetypes=[("Project Files", "*.pkl")])
            if file_path:
                with open(file_path, 'rb') as file:
                    project_data = pickle.load(file)
                    if 'console_text' in project_data:
                        self.console_textbox.configure(state="normal")
                        self.console_textbox.delete("1.0", "end")
                        self.console_textbox.insert("end", project_data['console_text'])
                        self.console_textbox.configure(state="disabled")
                    if 'details_text' in project_data:
                        self.details_textbox.configure(state="normal")
                        self.details_textbox.delete("1.0", "end")
                        self.details_textbox.insert("end", project_data['details_text'])
                        self.details_textbox.configure(state="disabled")
                    if 'files_text' in project_data:
                        self.files_console_textbox.configure(state="normal")
                        self.files_console_textbox.delete("1.0", "end")
                        self.files_console_textbox.insert("end", project_data['files_text'])
                        self.files_console_textbox.configure(state="disabled")
                    if 'app_details_dict' in project_data:
                        self.app_details_dict = project_data['app_details_dict']
                        if "App Name" in project_data.keys():
                            frap.name = project_data['App Name']
                            self.app_name_entry.delete(0, "end")
                            self.app_name_entry.insert(0, project_data['App Name'])
                            self.save_app_name_button_clicked()
                        if "Package Name" in self.app_details_dict.keys():
                            frap.package_name = self.app_details_dict["Package Name"]

                    if 'findings' in project_data:
                        if project_data['findings']:
                            # self.findings = project_data['findings']
                            for f in project_data['findings']:
                                if f not in self.findings:
                                    finding_checkbox = customtkinter.CTkCheckBox(self.scrollable_findings, text=f)
                                    finding_checkbox.grid(row=self.scrollable_findings_row, column=0, padx=10,
                                                          pady=(0, 10),
                                                          sticky="ew")
                                    self.scrollable_findings_row += 1
                                    self.findings.append(f)

                    if 'files_list' in project_data:
                        if len(frap.used_files) != 0:
                            frap.used_files = []
                            for widget in self.scrollable_files.winfo_children():  # destroy all exsits widgsts in files list
                                widget.destroy()
                        for file in project_data['files_list']:
                            frap.used_files.append(file)
                            self.create_new_file_opened(file)

                    if 'scripts_dict' in project_data:
                        if project_data['scripts_dict']:
                            for key, val in project_data['scripts_dict'].items():
                                if key not in self.default_bypasses_scripts.keys() and key not in self.scripts.keys():
                                    self.scripts[key] = val
                                    scriptSwitch = customtkinter.CTkSwitch(master=self.scrollable_frame,
                                                                           text=f"{key}")
                                    scriptSwitch.grid(row=self.scriptSwitchRow, column=0, padx=10, pady=(0, 20))
                                    self.scriptSwitchRow += 1
                                    self.scrollable_frame_switches[key] = scriptSwitch
                    if 'apk_path' in project_data:
                        self.app_details_dict["Apk Path"] = project_data['apk_path']
                        frap.apk_device_path = project_data['apk_path']
                    if 'data_path' in project_data:
                        self.app_details_dict["Data Path"] = project_data['data_path']
                        frap.data_path = project_data['data_path']
                    if 'pc_apk_path' in project_data:
                        frap.apk_pc_path = project_data['pc_apk_path']
                    if 'is_apk_pulled' in project_data:
                        if project_data['is_apk_pulled'] == True:
                            frap.is_apk_pulled == True
                            self.open_apk_button.grid()
                        elif project_data['is_apk_pulled'] == False:
                            self.open_apk_button.grid_remove()

                    self.update_details_tab_content()
                    self.print_to_console_textBox(text="Project loaded successfully.", color='green')
        except Exception as e:
            self.print_to_console_textBox(text=f"Error while loading project: {e}", color='red')


try:
    customtkinter.set_appearance_mode("Dark")  # Modes: "System" (standard), "Dark", "Light"
    customtkinter.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"
    customtkinter.set_widget_scaling(1.1)  # Set default scale

    GUIapp = App()

    frap = FridaApp()
    frap.try_to_load_device()

    device_connection_thread = threading.Thread(target=frap.check_if_device_is_connected)
    device_connection_thread.start()

    GUIapp.mainloop()

except KeyboardInterrupt:
    # device_thread.join()
    pass
# except Exception as e:
#     print(f"[-] Error occurred: {e}")
# device_thread.join()
