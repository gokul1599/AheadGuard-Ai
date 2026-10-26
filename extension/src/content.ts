// AheadGuard AI Content Script (Isolated & Privacy-First)
// Treats all page DOM content strictly as untrusted data.
// Does NOT inspect passwords, credit cards, OTPs, or private user inputs.

(function initAheadGuardContent() {
  // Listen for safe, internal extension messages only
  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (!message || typeof message !== "object") return;

    if (message.type === "PING_PAGE") {
      sendResponse({
        url: window.location.href,
        hostname: window.location.hostname,
        protocol: window.location.protocol,
        title: document.title,
      });
    }
  });
})();
