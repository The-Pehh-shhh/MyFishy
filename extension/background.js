// background.js
// Minimal background service worker as required by Manifest V3
chrome.runtime.onInstalled.addListener(() => {
    console.log("PhishGuard Extension installed successfully.");
});
