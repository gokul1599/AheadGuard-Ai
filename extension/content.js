"use strict";
(() => {
  // extension/src/content.ts
  (function initAheadGuardContent() {
    chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
      if (!message || typeof message !== "object") return;
      if (message.type === "PING_PAGE") {
        sendResponse({
          url: window.location.href,
          hostname: window.location.hostname,
          protocol: window.location.protocol,
          title: document.title
        });
      }
    });
  })();
})();
