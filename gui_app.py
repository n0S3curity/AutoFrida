import json
import os
import pickle
import subprocess
import sys
import threading
import time
import tkinter
import tkinter.messagebox
from tkinter import filedialog, messagebox

import customtkinter
from fpdf import FPDF


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

        self.finding_checkboxes_list = []
        self.findings = []
        self.app_details_dict = {}
        self.default_bypasses_scripts = {}

        # configure window
        self.title("Auto Frida Tool - Developed by n0S3curity")
        self.geometry(f"{1400}x{750}")

        # configure grid layout (4x4)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure((2, 3), weight=0)
        self.grid_rowconfigure((0, 1, 2), weight=1)

        # create sidebar frame with widgets
        # sidebar frame settings
        self.sidebar_frame = customtkinter.CTkScrollableFrame(self, width=180, corner_radius=0,scrollbar_button_color='#333333')
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
        self.sidebar_attach_button.grid(row=3, column=0, padx=20, pady=(0, 5))

        self.sidebar_detach_button = customtkinter.CTkButton(self.sidebar_frame, text="Detach Frida From App",
                                                             command=self.sidebar_button_detach_clicked)
        self.sidebar_detach_button.grid(row=4, column=0, padx=20, pady=(0, 15))

        self.sidebar_spawn_button.configure(fg_color='#00AC5E')
        self.sidebar_attach_button.configure(fg_color='#00AC5E')
        self.sidebar_detach_button.configure(fg_color='#00AC5E')

        self.GUIactions_label = customtkinter.CTkLabel(self.sidebar_frame, text="GUI Actions",
                                                       font=customtkinter.CTkFont(size=15))
        self.GUIactions_label.grid(row=5, column=0, padx=20, pady=(5, 5))
        self.sidebar_clear_button = customtkinter.CTkButton(self.sidebar_frame, text="Clear Current Console",
                                                            command=self.sidebar_button_clear_console_clicked)
        self.sidebar_clear_button.grid(row=6, column=0, padx=20, pady=(0, 5))
        self.sidebar_restart_button = customtkinter.CTkButton(self.sidebar_frame, text="Restart AutoFrida",
                                                              command=self.sidebar_button_Restart_clicked)
        self.sidebar_restart_button.grid(row=7, column=0, padx=20, pady=(0, 5))
        self.sidebar_reconnect_device_button = customtkinter.CTkButton(self.sidebar_frame, text="Reconnect Device",
                                                                       command=self.sidebar_button_reconnect_device_clicked)
        self.sidebar_reconnect_device_button.grid(row=8, column=0, padx=20, pady=(0, 5))
        self.sidebar_reconnect_device_button.configure(fg_color='#C67B00')

        self.sidebar_screenshot_button = customtkinter.CTkButton(self.sidebar_frame, text="Take Screenhot",
                                                            command=self.sidebar_button_take_screenshot_clicked)
        self.sidebar_screenshot_button.grid(row=9, column=0, padx=20, pady=(0, 5))

        self.sidebar_connect_frida_button = customtkinter.CTkButton(self.sidebar_frame, text="Connect Frida",
                                                                 command=self.run_frida_server_in_device)
        self.sidebar_connect_frida_button.grid(row=10, column=0, padx=20, pady=(0, 5))

        self.sidebar_kill_frida_button = customtkinter.CTkButton(self.sidebar_frame, text="Kill Frida",
                                                                    command=self.kill_frida_server_in_device)
        self.sidebar_kill_frida_button.grid(row=11, column=0, padx=20, pady=(0, 5))

        # sidebar modes
        self.settings_label = customtkinter.CTkLabel(self.sidebar_frame, text="Project",
                                                     font=customtkinter.CTkFont(size=15))
        self.settings_label.grid(row=12, column=0, padx=20, pady=(20, 5))

        self.sidebar_spawn_button = customtkinter.CTkButton(self.sidebar_frame, text="Save Project",
                                                            command=self.sidebar_button_save_project_clicked)
        self.sidebar_spawn_button.grid(row=13, column=0, padx=20, pady=(0, 5))
        self.sidebar_spawn_button = customtkinter.CTkButton(self.sidebar_frame, text="Load Project",
                                                            command=self.sidebar_button_load_project_clicked)
        self.sidebar_spawn_button.grid(row=14, column=0, padx=20, pady=(0, 5))

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
        self.consoles_tabview.add("File Explorer")
        self.consoles_tabview.add("Classes")
        self.consoles_tabview.add("Logs")
        self.consoles_tabview.add("Exploit")

        self.file_explorer_label = customtkinter.CTkLabel(self.consoles_tabview.tab("File Explorer"), text='Path:',font=customtkinter.CTkFont(size=15))
        self.file_explorer_label.grid(row=0, column=0, padx=0, pady=(5, 5), sticky="w")
        self.file_explorer_entry = customtkinter.CTkEntry(self.consoles_tabview.tab("File Explorer"), placeholder_text="Path",
                                                     font=("consolas", 15))
        self.file_explorer_entry.grid(row=1, column=0, columnspan=100, padx=(0, 0), pady=(0, 0), sticky="nsew")
        self.consoles_tabview.tab("File Explorer").grid_columnconfigure(0, weight=1)
        self.consoles_tabview.tab("File Explorer").grid_rowconfigure(2, weight=1)
        self.file_explorer_entry.bind("<KeyPress>", self.file_explorer_serach_key_pressed)
        self.scrollable_file_explorer = customtkinter.CTkScrollableFrame(self.consoles_tabview.tab("File Explorer"),
                                                                 label_text="Files List",scrollbar_button_color='#333333')
        self.scrollable_file_explorer.grid(row=2, rowspan=100, column=0, padx=(5, 5), pady=(5, 5), sticky="nsew")
        self.scrollable_file_explorer.grid_rowconfigure(0, weight=1)
        self.scrollable_file_explorer.grid_columnconfigure(0, weight=1)


        self.exploit_textbox = customtkinter.CTkTextbox(self.consoles_tabview.tab("Exploit"), state="disabled",border_width=2,font=("consolas", 15), wrap='none')
        self.exploit_textbox.grid(row=0, column=0,columnspan=3, padx=(0, 0), pady=(0, 5), sticky="nsew")

        self.exported_activities_menu = customtkinter.CTkOptionMenu(self.consoles_tabview.tab("Exploit"),dynamic_resizing=True, values=[])
        self.exported_activities_menu.grid(row=1, column=0, padx=0, pady=(5, 5), sticky="ew")
        self.exported_activities_menu.set("Exported Activities")
        self.activities_button = customtkinter.CTkButton(self.consoles_tabview.tab("Exploit"), text="Open Activity",
                                                            command=self.activities_button_clicked)
        self.activities_button.grid(row=1, column=1, padx=10, pady=(5, 5), sticky="ew")


        self.exported_services_menu = customtkinter.CTkOptionMenu(self.consoles_tabview.tab("Exploit"), dynamic_resizing=True, values=[])
        self.exported_services_menu.grid(row=2, column=0, padx=0, pady=(5, 5), sticky="ew")
        self.exported_services_menu.set("Exported Services")

        self.exported_recievers_menu = customtkinter.CTkOptionMenu(self.consoles_tabview.tab("Exploit"),dynamic_resizing=True, values=[])
        self.exported_recievers_menu.grid(row=3, column=0, padx=0, pady=(5, 5), sticky="ew")
        self.exported_recievers_menu.set("Exported Receivers")


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
                                                                 label_text="Files List",scrollbar_button_color='#333333')
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
        self.consoles_tabview.tab("Exploit").grid_rowconfigure(0, weight=1)
        self.consoles_tabview.tab("Exploit").grid_columnconfigure(0, weight=1)

        self.print_to_console_textBox(text="Console Output\n", color='green')
        self.print_to_files_console_textbox(text="Files Management Console\n", color='green')
        self.print_to_classes_console_textbox(text="Classes Console\n", color='green')
        self.print_to_logs_console_textbox(text="Logs Console\n", color='green')
        self.print_to_exploit_textBox(text="Exploit Console\n", color='green')

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

        self.exploit_textbox.tag_config('red', foreground='#FF0000')
        self.exploit_textbox.tag_config('green', foreground='#2AFF00')
        self.exploit_textbox.tag_config('orange', foreground='#FF9700')
        self.exploit_textbox.tag_config('blue', foreground='#ABB3FF')

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
        self.analyze_strings = customtkinter.CTkButton(self.analyzeTabview.tab("Static"), text="Analyze APK Strings",
                                                       command=self.analyze_strings_button_clicked)
        self.analyze_strings.grid(row=0, column=0, padx=75, pady=(5, 5))

        self.pull_apk_button = customtkinter.CTkButton(self.analyzeTabview.tab("Static"), text="Pull APK file",
                                                       command=self.pull_apk_button_clicked)
        self.pull_apk_button.grid(row=1, column=0, padx=75, pady=(0, 5))

        self.open_apk_button = customtkinter.CTkButton(self.analyzeTabview.tab("Static"), text="Open APK file",
                                                       command=self.open_apk_button_clicked)
        self.open_apk_button.grid(row=2, column=0, padx=75, pady=(0, 5))
        self.open_apk_button.grid_remove()

        self.show_current_activity_button = customtkinter.CTkButton(self.analyzeTabview.tab("Static"),
                                                                    text="Show Current Activity",
                                                                    command=self.show_current_activity_button_clicked)
        self.show_current_activity_button.grid(row=3, column=0, padx=75, pady=(0, 5))

        self.sign_apk_button = customtkinter.CTkButton(self.analyzeTabview.tab("Static"),
                                                                    text="Sign APK file",
                                                                    command=self.sign_apk_button_clicked)
        self.sign_apk_button.grid(row=4, column=0, padx=75, pady=(0, 5))


        self.tabview.add("Findings")
        self.scrollable_findings = customtkinter.CTkScrollableFrame(self.tabview.tab("Findings"),scrollbar_button_color='#333333')
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


        # self. menu = customtkinter.CTkOptionMenu(self.tabview.tab("DevicePackages"),
        #                                                         dynamic_resizing=True, values=[])
        # self.device_packages_menu.grid(row=0, column=0, padx=20, pady=(20, 10))
        # self.device_packages_menu.set("Apps not loaded")



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
        self.scrollable_frame = customtkinter.CTkScrollableFrame(self, label_text="Scripts Section",scrollbar_button_color='#333333')
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


    def file_explorer_serach_key_pressed(self,event):
        if not (event.char.isalpha() or event.char in "!@#$%^&*()_+{}|:\"<>?"):
            cat_directory_thread = threading.Thread(target=self.frap.ls_directory_from_device)
            cat_directory_thread.start()
    def run_frida_server_in_device(self):
        run_frida_thread = threading.Thread(target=self.frap.run_frida_in_device)
        run_frida_thread.start()
    def kill_frida_server_in_device(self):
        kill_frida_thread = threading.Thread(target=self.frap.kill_frida_in_device)
        kill_frida_thread.start()
    def sidebar_button_detach_clicked(self):
        detach_frida_thraed = threading.Thread(target=self.frap.detach_frida)
        detach_frida_thraed.start()
    def activities_button_clicked(self):
        selected_activity = self.exported_activities_menu.get()

        if selected_activity != "Exported Activities":  # Check if a valid activity is selected
            command = f"adb shell am start -n {selected_activity}"
            subprocess.call(command, shell=True)
            self.print_to_exploit_textBox(text=f"Activity opened:{selected_activity}", color='green')
        else:
            self.print_to_exploit_textBox(text="Please select a valid activity to launch.",color='red')
    def set_frida_app(self, frida_app_instance):
        self.frap = frida_app_instance

    def sign_apk_button_clicked(self):
        self.print_to_console_textBox(text=f"[WARNNING] Java (JDK8) has to be installed on your PC ans also be in PATH.", color='orange')
        apk_file_path = filedialog.askopenfilename(title="Select APK file to sign", filetypes=[("APK files", "*.apk")])
        if apk_file_path:
            sign_apk_thread = threading.Thread(target=self.frap.sign_apk_file(apk_file_path))
            sign_apk_thread.start()
        else:
            self.print_to_console_textBox(text="No APK file selected.", color='orange')
    def show_current_activity_button_clicked(self):
        show_command = 'adb shell dumpsys window | find "mCurrentFocus"'
        try:
            result = subprocess.run(show_command, shell=True, check=True, capture_output=True, text=True)
            current_activity = result.stdout.strip().split('/')[-1].replace("}", "")
            self.print_to_console_textBox(text=f"Current Activity: {current_activity}", color='blue')
        except subprocess.CalledProcessError as e:
            self.print_to_console_textBox(text=f"Error in show_current_activity_button_clicked: {e}", color='red')

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

    def analyze_strings_button_clicked(self):
        analyze = threading.Thread(target=lambda: self.frap.analyze_strings_on_apk_file)
        analyze.start()
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
            self.print_to_files_console_textbox(text=f"Error:print_target_file_thread\n{e}", color='red')

    def print_traget_file_clicked(self, filename):
        print_thread = threading.Thread(target=self.print_traget_file_thread(filename))
        print_thread.start()

    def open_apk_button_clicked(self):
        try:
            if os.path.exists(self.frap.apk_pc_path):
                os.startfile(self.frap.apk_pc_path)
                self.print_to_console_textBox(text=f"APK opened successfully.", color='green')
            else:
                self.print_to_console_textBox(text=f"APK path not exist: {self.frap.apk_pc_path}", color='orange')
        except Exception as e:
            self.print_to_console_textBox(text=f"Error: {e}", color='red')

    def pull_apk_button_clicked(self):
        pull_thread = threading.Thread(target=self.frap.pull_apk_file_thread)
        pull_thread.start()

    def add_finding_to_finding_tab(self, name, check_var=None, Cvar=None):
        if name not in self.findings:
            self.findings.append(name)
            finding_checkbox = customtkinter.CTkCheckBox(self.scrollable_findings, text=name, variable=Cvar , onvalue=1, offvalue=0)
            finding_checkbox.grid(row=self.scrollable_findings_row, column=0, padx=10, pady=(0, 10), sticky="ew")
            self.finding_checkboxes_list.append(finding_checkbox)
            self.scrollable_findings_row += 1
            self.print_to_console_textBox(text=f"[Finding] {name}", color='orange')

    def export_findings_button_clicked(self):
        selected_findings = []
        # Iterate through the checkboxes and check which ones are toggled
        for checkbox in self.finding_checkboxes_list:
            if checkbox.get() == 1 :
                selected_findings.append(checkbox.cget("text"))
        # Load the findings from the JSON file
        with open('Lists/findings.json', 'r') as file:
            all_findings = json.load(file)
        # Filter out the selected findings from the loaded JSON data
        selected_findings_data = [finding for finding in all_findings['findings'] if
                                  finding['issue'] in selected_findings]

        # Generate a PDF file and add the selected findings
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        for finding in selected_findings_data:
            pdf.set_font("Arial", "B", size=14)
            pdf.cell(w=200, h=10,txt=f"Finding: {finding['issue']}", ln=True)
            pdf.set_font("Arial", size=12)
            pdf.multi_cell(0, 10, txt=f"Description: {finding['description']}", align='L')
            pdf.ln()

        pdf.output("exported_findings.pdf")

        # Optionally, print the selected findings to the console
        for finding_name in selected_findings:
            self.print_to_console_textBox(text=f"[Exported Finding] {finding_name}", color='green')

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

    def print_to_all_consoles(self, text, color=''):
        self.print_to_console_textBox(text,color=color)
        self.print_to_exploit_textBox(text,color=color)
        self.print_to_files_console_textbox(text,color=color)
        self.print_to_logs_console_textbox(text,color=color)


    def print_to_exploit_textBox(self, text, color=''):
        self.exploit_textbox.configure(state="normal")
        if color != '':
            self.exploit_textbox.insert("end", text + "\n", color)
        else:
            self.exploit_textbox.insert("end", text + "\n")
        self.exploit_textbox.configure(state="disabled")
        self.exploit_textbox.yview(tkinter.END)


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
        script_to_auto_toggle = ['Android_Log_class_Watcher', 'Android_file_guard','Android_discover_exported_components']
        self.default_bypasses_scripts = {file_name[:-3]: open(os.path.join("DefaultScripts/", file_name)).read() for
                                         file_name in os.listdir("DefaultScripts/")}
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
        spawn_button_thread = threading.Thread(target=self.frap.spawn_frida)
        spawn_button_thread.start()

    def sidebar_button_attach_clicked(self):
        attach_button_thread = threading.Thread(target=self.frap.attach_frida)
        attach_button_thread.start()

    def sidebar_button_Restart_clicked(self):
        confirmation = messagebox.askokcancel("Confirmation", "Are you sure you want to restart?")

        if confirmation:
            current_program_exec = sys.executable
            os.execl(current_program_exec, current_program_exec, *sys.argv)
        else:
            pass  # User cancelled restart, do nothing


    def sidebar_button_take_screenshot_clicked(self):
        screenshot_thread = threading.Thread(target=self.frap.take_screenshot)
        screenshot_thread.start()


    def sidebar_button_reconnect_device_clicked(self):
        self.print_to_console_textBox(text="Looking for device connection.., wait 2 sec after connection",
                                      color='orange')
        self.frap.device_is_connected = False

    def sidebar_button_clear_console_clicked(self):
        selected_tab = self.consoles_tabview.get()
        tab = self.consoles_tabview.tab(selected_tab)
        if selected_tab == "Console":
            self.console_textbox.configure(state="normal")
            self.console_textbox.delete("2.0", "end")  # Clear the entire content
            self.console_textbox.insert("end", "\n")
            self.console_textbox.configure(state="disabled")
        elif selected_tab == "File Manager":
            self.files_console_textbox.configure(state="normal")
            self.files_console_textbox.delete("2.0", "end")  # Clear the entire content
            self.files_console_textbox.insert("end", "\n")
            self.files_console_textbox.configure(state="disabled")
        elif selected_tab == "Logs":
            self.logs_textbox.configure(state="normal")
            self.logs_textbox.delete("2.0", "end")  # Clear the entire content
            self.logs_textbox.insert("end", "\n")
            self.logs_textbox.configure(state="disabled")
        elif selected_tab == "Classes":
            self.classes_console_textbox.configure(state="normal")
            self.classes_console_textbox.delete("2.0", "end")  # Clear the entire content
            self.classes_console_textbox.insert("end", "\n")
            self.classes_console_textbox.configure(state="disabled")

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
        load_all_apps_thread = threading.Thread(target=self.frap.load_all_apps)
        load_all_apps_thread.start()

    def load_running_apps_button_clicked(self):
        load_apps_thread = threading.Thread(target=self.frap.load_running_apps)
        load_apps_thread.start()

    def load_selected_app_button_clicked(self):
        selected_app = self.device_packages_menu.get()
        if selected_app == 'List updated!' or selected_app == 'No apps found!' or selected_app == "Apps not loaded":
            self.print_to_console_textBox(text=f"No app selected,select from list or insert manually.", color='orange')
            return
        self.frap.name = self.app_details_dict["App Name"] = selected_app.split("|")[0].strip()
        self.frap.package_name = self.app_details_dict["Package Name"] = selected_app.split("|")[1].strip()
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
                    'files_list': self.frap.used_files,
                    'scripts_dict': {},
                    'apk_path': self.frap.apk_device_path,
                    'data_path': self.frap.data_path,
                    'pc_apk_path': self.frap.apk_pc_path,
                    'is_apk_pulled': self.frap.is_apk_pulled
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
                            self.frap.name = project_data['App Name']
                            self.app_name_entry.delete(0, "end")
                            self.app_name_entry.insert(0, project_data['App Name'])
                            self.save_app_name_button_clicked()
                        if "Package Name" in self.app_details_dict.keys():
                            self.frap.package_name = self.app_details_dict["Package Name"]

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
                        if len(self.frap.used_files) != 0:
                            self.frap.used_files = []
                            for widget in self.scrollable_files.winfo_children():  # destroy all exsits widgsts in files list
                                widget.destroy()
                        for file in project_data['files_list']:
                            self.frap.used_files.append(file)
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
                        self.frap.apk_device_path = project_data['apk_path']
                    if 'data_path' in project_data:
                        self.app_details_dict["Data Path"] = project_data['data_path']
                        self.frap.data_path = project_data['data_path']
                    if 'pc_apk_path' in project_data:
                        self.frap.apk_pc_path = project_data['pc_apk_path']
                    if 'is_apk_pulled' in project_data:
                        if project_data['is_apk_pulled'] == True:
                            self.frap.is_apk_pulled == True
                            self.open_apk_button.grid()
                        elif project_data['is_apk_pulled'] == False:
                            self.open_apk_button.grid_remove()

                    self.update_details_tab_content()
                    self.print_to_console_textBox(text="Project loaded successfully.", color='green')
        except Exception as e:
            self.print_to_console_textBox(text=f"Error while loading project: {e}", color='red')
