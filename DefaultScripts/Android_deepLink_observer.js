Java.perform(function() {
    var Intent = Java.use("android.content.Intent");
    Intent.getData.implementation = function() {
        var data = {};
        var action = this.getAction() !== null ? this.getAction().toString() : false;
        if (action) {
            data["Intent-Get-Data"] = true;
            data["Activity"] = this.getComponent().getClassName();
            data["Action"] = action;

            // Get categories associated with the intent
            var categories = this.getCategories();
            if (categories !== null) {
                var categoriesList = Java.cast(categories, Java.use("java.util.ArrayList"));
                var categoryArray = [];
                for (var i = 0; i < categoriesList.size(); i++) {
                    categoryArray.push(categoriesList.get(i).toString());
                }
                data["Categories"] = categoryArray;
            }
            else{
            data["Categories"] = "None"
            }

            var uri = this.getData();
            if (uri !== null) {
                data["Data"] = {
                    "URI": uri.toString()
                };
            } else {
                // No data supplied, do nothing here
            }

            var extras = this.getExtras();
            if (extras !== null) {
                var extrasData = {};
                var keys = extras.keySet().toArray();
                for (var i = 0; i < keys.length; i++) {
                    var key = keys[i].toString();
                    var value = extras.get(key);
                    // Convert Java objects to a more readable format
                    extrasData[key] = convertJavaObjectToString(value);
                }
                data["Extras"] = extrasData;
            } else {
                data["Extras"] = "No extras supplied.";
            }

            send({"type": "URIscheme", "data": JSON.stringify(data)});
        }
        return this.getData();
    }
});
