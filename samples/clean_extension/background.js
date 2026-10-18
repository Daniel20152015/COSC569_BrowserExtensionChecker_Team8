chrome.storage.local.get(
    ["theme"],
    function(result) {
        console.log(result);
    }
);

chrome.tabs.query(
    {
        active: true,
        currentWindow: true
    },
    function(tabs) {
        console.log(tabs.length);
    }
);