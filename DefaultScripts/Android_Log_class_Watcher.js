Java.perform(function () {var Log = Java.use('android.util.Log');
    ['d', 'e', 'i', 'v', 'w'].forEach(function(level) {
        Log[level].overload('java.lang.String', 'java.lang.String').implementation = function(tag, msg) {
        var logMessage = tag + ': ' + msg;
        send({LoggedMessage: logMessage });
        return this[level](tag, msg);
};
});
});