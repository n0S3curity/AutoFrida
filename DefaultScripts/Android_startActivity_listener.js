Java.perform(function () {
    var Activity = Java.use('android.app.Activity');
    var Intent = Java.use('android.content.Intent');

    Activity.startActivity.overload('android.content.Intent').implementation = function (intent) {
        var data = {};
        var component = intent.getComponent();
        if (component !== null) {
            data['Activity'] = component.getClassName();
        }
        data['Action'] = intent.getAction();
        data['Category'] = intent.getCategories();

        var extras = intent.getExtras();
        if (extras !== null) {
            var extrasMap = {};

            // Iterate over the keys in the Bundle and extract key-value pairs
            var keys = extras.keySet().toArray();
            for (var i = 0; i < keys.length; i++) {
                var key = keys[i].toString();
                var value = extras.get(keys[i]);

                // Convert the value to its string representation
                if (value !== null && value.getClass().isArray()) {
                    extrasMap[key] = arrayToString(value);
                } else {
                    extrasMap[key] = value ? value.toString() : null;
                }
            }

            data['Extras'] = extrasMap;
        } else {
            data['Extras'] = null;
        }

        console.log(JSON.stringify(data));
        send({"type": "ActivityStart", "data": JSON.stringify(data)});

        // Call the original startActivity method
        this.startActivity.overload('android.content.Intent').call(this, intent);
    };

    // Helper function to convert arrays to string
    function arrayToString(arr) {
        var result = '[';
        for (var i = 0; i < arr.length; i++) {
            if (i > 0) result += ', ';
            result += arr[i] ? arr[i].toString() : null;
        }
        result += ']';
        return result;
    }
});
