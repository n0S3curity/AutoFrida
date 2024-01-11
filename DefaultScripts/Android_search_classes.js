
    Java.perform(function() {
        var allClasses = [];

        // Function to enumerate loaded classes and send them back to Python
        function enumerateAndSendClasses() {
            Java.enumerateLoadedClasses({
                onMatch: function(cls) {
                    allClasses.push(cls);
                },
                onComplete: function() {
                }
            });
        }

        // Enumerate and send classes on script initialization
        enumerateAndSendClasses();

        function listenForMessages() {
            // Listen for messages from Python and perform class search
            recv('classToSearch', function(className) {var searchTerm = className.payload.toLowerCase(); // Convert search term to lowercase

        var searchResults = allClasses.filter(function(cls) {
            return cls.toLowerCase().includes(searchTerm); // Convert class name to lowercase
        });

        send({ type: 'ClassesSearchResult', payload: searchResults });
        setTimeout(listenForMessages, 100);
            });
        }

        // Start listening for messages
        listenForMessages();
    });