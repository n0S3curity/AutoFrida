import threading

import customtkinter
from gui_app import App
from frida_app import FridaApp


try:
    customtkinter.set_appearance_mode("Dark")  # Modes: "System" (standard), "Dark", "Light"
    customtkinter.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"
    customtkinter.set_widget_scaling(1.1)  # Set default scale

    GUIapp = App()
    GUIapp.iconbitmap("icon.ico")
    frap = FridaApp(GUIapp)
    frap.try_to_load_device()
    GUIapp.set_frida_app(frap)
    device_connection_thread = threading.Thread(target=frap.check_if_device_is_connected)
    device_connection_thread.start()

    device_activity_checker = threading.Thread(target=frap.check_current_activity)
    device_activity_checker.start()

    GUIapp.mainloop()

except Exception as e:
    print(f"[-] Error occurred in main: {e}")
