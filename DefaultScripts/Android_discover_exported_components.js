// Frida script
function main() {
    Java.perform(function() {
        var ActivityThread = Java.use("android.app.ActivityThread");
        var PackageManager = Java.use("android.content.pm.PackageManager");

        var context = ActivityThread.currentApplication().getApplicationContext();
        var packageName = context.getPackageName();
        var packageInfo = context.getPackageManager().getPackageInfo(packageName,
            PackageManager.GET_ACTIVITIES.value | PackageManager.GET_SERVICES.value | PackageManager.GET_RECEIVERS.value
        );

        var exportedActivities = [];
        var exportedServices = [];
        var exportedReceivers = [];

        function logExportedComponents(componentInfoArray, componentType) {
            if (componentInfoArray) {
                for (var i = 0; i < componentInfoArray.length; i++) {
                    var component = componentInfoArray[i];
                    if (component.exported.value) {
                        if (componentType === "Activity") {
                            exportedActivities.push(packageName + "/" + component.name.value);
                        } else if (componentType === "Service") {
                            exportedServices.push(packageName + "/" + component.name.value);
                        } else if (componentType === "Receiver") {
                            exportedReceivers.push(packageName + "/" + component.name.value);
                        }
                    }
                }
            }
        }

        logExportedComponents(packageInfo.activities.value, "Activity");
        logExportedComponents(packageInfo.services.value, "Service");
        logExportedComponents(packageInfo.receivers.value, "Receiver");

        send({
            "exportedActivities": exportedActivities,
            "exportedServices": exportedServices,
            "exportedReceivers": exportedReceivers
        });
    });
}

setTimeout(function() {
    Java.scheduleOnMainThread(main);
}, 50);
