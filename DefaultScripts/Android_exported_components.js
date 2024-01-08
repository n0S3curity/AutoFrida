 function main() {
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
}, 50);