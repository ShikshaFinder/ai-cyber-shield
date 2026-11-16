// Enhanced Content Script for BugBounty Capture Agent
// Handles Web Storage Extraction and DOM Security Analysis

class WebStorageCollector {
  constructor() {
    this.storageData = {
      localStorage: {},
      sessionStorage: {},
      cookies: {},
      timestamp: Date.now(),
    };
  }

  collectLocalStorage() {
    try {
      // Check if localStorage is available
      if (typeof Storage === "undefined" || !window.localStorage) {
        console.log("localStorage not available");
        return;
      }

      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key) {
          const value = localStorage.getItem(key);
          this.storageData.localStorage[key] = {
            value: value,
            size: value ? value.length : 0,
            timestamp: Date.now(),
          };
        }
      }
    } catch (error) {
      console.error("Error collecting localStorage:", error);
      this.storageData.localStorage = { error: error.message };
    }
  }

  collectSessionStorage() {
    try {
      // Check if sessionStorage is available
      if (typeof Storage === "undefined" || !window.sessionStorage) {
        console.log("sessionStorage not available");
        return;
      }

      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        if (key) {
          const value = sessionStorage.getItem(key);
          this.storageData.sessionStorage[key] = {
            value: value,
            size: value ? value.length : 0,
            timestamp: Date.now(),
          };
        }
      }
    } catch (error) {
      console.error("Error collecting sessionStorage:", error);
      this.storageData.sessionStorage = { error: error.message };
    }
  }

  collectCookies() {
    try {
      // Check if document.cookie is accessible
      if (!document || typeof document.cookie === "undefined") {
        console.log("Document cookies not accessible");
        return;
      }

      const cookieString = document.cookie;
      if (!cookieString) {
        console.log("No cookies found");
        return;
      }

      const cookies = cookieString.split(";");
      cookies.forEach((cookie) => {
        const [name, value] = cookie.trim().split("=");
        if (name && value) {
          this.storageData.cookies[name] = {
            value: value,
            size: value.length,
            timestamp: Date.now(),
          };
        }
      });
    } catch (error) {
      console.error("Error collecting cookies:", error);
      this.storageData.cookies = { error: error.message };
    }
  }

  collectAll() {
    this.collectLocalStorage();
    this.collectSessionStorage();
    this.collectCookies();
    return this.storageData;
  }
}

class DOMSecurityAnalyzer {
  constructor() {
    this.vulnerabilities = [];
    this.analysisResults = {
      forms: [],
      xssSinks: [],
      insecureElements: [],
      timestamp: Date.now(),
    };
  }

  analyzeForms() {
    const forms = document.querySelectorAll("form");
    forms.forEach((form, index) => {
      const formData = {
        index: index,
        action: form.action,
        method: form.method,
        id: form.id,
        className: form.className,
        insecure: false,
        issues: [],
      };

      // Check for insecure HTTP action URLs
      if (form.action && form.action.startsWith("http://")) {
        formData.insecure = true;
        formData.issues.push({
          type: "insecure_protocol",
          description: "Form submits to insecure HTTP URL",
          severity: "HIGH",
          url: form.action,
        });
      }

      // Check for missing CSRF protection
      const csrfToken = form.querySelector(
        'input[name*="csrf"], input[name*="token"], input[name*="nonce"]'
      );
      if (!csrfToken && form.method.toLowerCase() === "post") {
        formData.issues.push({
          type: "missing_csrf",
          description: "Form lacks CSRF protection token",
          severity: "MEDIUM",
        });
      }

      // Check for sensitive input fields
      const sensitiveInputs = form.querySelectorAll(
        'input[type="password"], input[name*="password"], input[name*="token"], input[name*="secret"]'
      );
      sensitiveInputs.forEach((input) => {
        formData.issues.push({
          type: "sensitive_input",
          description: "Sensitive input field detected",
          severity: "INFO",
          fieldName: input.name,
          fieldType: input.type,
        });
      });

      this.analysisResults.forms.push(formData);
    });
  }

  analyzeXSSSinks() {
    // Common XSS sinks
    const xssSinks = [
      "innerHTML",
      "outerHTML",
      "insertAdjacentHTML",
      "document.write",
      "document.writeln",
      "eval",
      "setTimeout",
      "setInterval",
    ];

    // Common XSS sources
    const xssSources = [
      "location.hash",
      "location.search",
      "location.href",
      "document.referrer",
      "document.URL",
      "document.documentURI",
      "document.baseURI",
    ];

    // Analyze script tags for potential XSS
    const scripts = document.querySelectorAll("script");
    scripts.forEach((script, index) => {
      const scriptContent = script.textContent || script.innerHTML;

      // Check for dynamic content injection
      xssSources.forEach((source) => {
        if (scriptContent.includes(source)) {
          this.analysisResults.xssSinks.push({
            type: "script_xss_source",
            description: `Script uses potentially dangerous source: ${source}`,
            severity: "MEDIUM",
            scriptIndex: index,
            source: source,
            content: scriptContent.substring(0, 200) + "...",
          });
        }
      });
    });

    // Analyze inline event handlers
    const elementsWithEvents = document.querySelectorAll(
      "[onclick], [onload], [onerror], [onmouseover]"
    );
    elementsWithEvents.forEach((element) => {
      const eventHandlers = [];
      ["onclick", "onload", "onerror", "onmouseover"].forEach((event) => {
        if (element[event]) {
          eventHandlers.push({
            event: event,
            handler: element[event],
          });
        }
      });

      if (eventHandlers.length > 0) {
        this.analysisResults.xssSinks.push({
          type: "inline_event_handler",
          description: "Element uses inline event handlers",
          severity: "MEDIUM",
          element: element.tagName,
          eventHandlers: eventHandlers,
        });
      }
    });
  }

  analyzeInsecureElements() {
    // Check for elements that might be security risks
    const iframes = document.querySelectorAll("iframe");
    iframes.forEach((iframe, index) => {
      if (iframe.src && iframe.src.startsWith("http://")) {
        this.analysisResults.insecureElements.push({
          type: "insecure_iframe",
          description: "Insecure iframe source",
          severity: "MEDIUM",
          src: iframe.src,
          index: index,
        });
      }
    });

    // Check for external scripts
    const externalScripts = document.querySelectorAll("script[src]");
    externalScripts.forEach((script, index) => {
      if (script.src && script.src.startsWith("http://")) {
        this.analysisResults.insecureElements.push({
          type: "insecure_external_script",
          description: "Insecure external script source",
          severity: "MEDIUM",
          src: script.src,
          index: index,
        });
      }
    });

    // Check for external stylesheets
    const externalStyles = document.querySelectorAll('link[rel="stylesheet"]');
    externalStyles.forEach((style, index) => {
      if (style.href && style.href.startsWith("http://")) {
        this.analysisResults.insecureElements.push({
          type: "insecure_external_style",
          description: "Insecure external stylesheet source",
          severity: "LOW",
          href: style.href,
          index: index,
        });
      }
    });
  }

  analyzeAll() {
    this.analyzeForms();
    this.analyzeXSSSinks();
    this.analyzeInsecureElements();

    // Combine all vulnerabilities
    this.vulnerabilities = [
      ...this.analysisResults.forms.filter(
        (f) => f.insecure || f.issues.length > 0
      ),
      ...this.analysisResults.xssSinks,
      ...this.analysisResults.insecureElements,
    ];

    return {
      vulnerabilities: this.vulnerabilities,
      analysisResults: this.analysisResults,
      summary: {
        totalForms: this.analysisResults.forms.length,
        insecureForms: this.analysisResults.forms.filter((f) => f.insecure)
          .length,
        xssSinks: this.analysisResults.xssSinks.length,
        insecureElements: this.analysisResults.insecureElements.length,
        totalVulnerabilities: this.vulnerabilities.length,
      },
    };
  }
}

// Message listener for communication with background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log("Content script received message:", message);

  try {
    switch (message.action) {
      case "collectWebStorage":
        try {
          const storageCollector = new WebStorageCollector();
          const storageData = storageCollector.collectAll();

          sendResponse({
            success: true,
            data: storageData,
          });
        } catch (error) {
          console.error("Error in collectWebStorage:", error);
          sendResponse({
            success: false,
            error: error.message,
            data: {
              localStorage: {},
              sessionStorage: {},
              cookies: {},
              error: error.message,
            },
          });
        }
        break;

      case "analyzeDOMSecurity":
        try {
          const domAnalyzer = new DOMSecurityAnalyzer();
          const analysisResults = domAnalyzer.analyzeAll();

          sendResponse({
            success: true,
            vulnerabilities: analysisResults.vulnerabilities,
            analysisResults: analysisResults.analysisResults,
            summary: analysisResults.summary,
          });
        } catch (error) {
          console.error("Error in analyzeDOMSecurity:", error);
          sendResponse({
            success: false,
            error: error.message,
            vulnerabilities: [],
            analysisResults: {
              forms: [],
              xssSinks: [],
              insecureElements: [],
            },
            summary: {
              totalVulnerabilities: 0,
              highSeverity: 0,
              mediumSeverity: 0,
              lowSeverity: 0,
            },
          });
        }
        break;

      default:
        sendResponse({
          success: false,
          error: "Unknown action",
        });
    }
  } catch (error) {
    console.error("Error in message listener:", error);
    sendResponse({
      success: false,
      error: error.message,
    });
  }

  return true; // Keep message channel open for async response
});

// Auto-collect data when page loads
document.addEventListener("DOMContentLoaded", () => {
  console.log("BugBounty Capture Agent: Content script loaded");

  // Wait a bit for dynamic content to load
  setTimeout(() => {
    const storageCollector = new WebStorageCollector();
    const domAnalyzer = new DOMSecurityAnalyzer();

    const storageData = storageCollector.collectAll();
    const analysisResults = domAnalyzer.analyzeAll();

    // Send data to background script
    chrome.runtime.sendMessage({
      action: "webStorageCollected",
      data: storageData,
    });

    chrome.runtime.sendMessage({
      action: "domAnalysisComplete",
      vulnerabilities: analysisResults.vulnerabilities,
      analysisResults: analysisResults.analysisResults,
      summary: analysisResults.summary,
    });
  }, 2000);
});

// Monitor for dynamic content changes
let observer;

function startObserver() {
  // Cleanup existing observer if any
  if (observer) {
    observer.disconnect();
  }

  observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      if (mutation.type === "childList" && mutation.addedNodes.length > 0) {
        // New elements added, re-analyze if needed
        setTimeout(() => {
          const domAnalyzer = new DOMSecurityAnalyzer();
          const analysisResults = domAnalyzer.analyzeAll();

          if (chrome.runtime?.id) {
            // Check if extension context is still valid

            chrome.runtime.sendMessage({
              action: "domAnalysisComplete",
              vulnerabilities: analysisResults.vulnerabilities,
              analysisResults: analysisResults.analysisResults,
              summary: analysisResults.summary,
            });
          }
        }, 1000);
      }
    });
  });

  // Start observing
  if (document.body) {
    observer.observe(document.body, {
      childList: true,
      subtree: true,
    });
  }
}

// Cleanup when page unloads
window.addEventListener("beforeunload", () => {
  if (observer) {
    observer.disconnect();
  }
});

// Start observing when DOM is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", startObserver);
} else {
  startObserver();
}

console.log("BugBounty Capture Agent: Enhanced content script initialized");
