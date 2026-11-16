document.addEventListener("DOMContentLoaded", function () {
  const startButton = document.getElementById("start");
  const stopButton = document.getElementById("stop");
  const downloadCategorizedButton = document.getElementById("downloadCategorized");
  const goBackButton = document.getElementById("goBack");
  const filenameInput = document.getElementById("filename");
  const statusDiv = document.getElementById("status");
  const statusDot = document.getElementById("statusDot");
  const requestCountSpan = document.getElementById("requestCount");
  const lastCaptureSpan = document.getElementById("lastCapture");
  const cloudCountSpan = document.getElementById("cloudCount");
  const cloudPercentageSpan = document.getElementById("cloudPercentage");
  const topProviderDiv = document.getElementById("topProvider");

  // Local harness controls
  const harnessUrlInput = document.getElementById("harnessUrl");
  const harnessTokenInput = document.getElementById("harnessToken");
  const scanModeSelect = document.getElementById("scanMode");
  const scanScopeInput = document.getElementById("scanScope");
  const saveHarnessButton = document.getElementById("saveHarness");
  const sendToHarnessButton = document.getElementById("sendToHarness");
  const harnessStatus = document.getElementById("harnessStatus");

  // Load saved harness settings.
  chrome.storage.local.get(["harnessSettings"], function (result) {
    const s = result.harnessSettings || {};
    if (s.url) harnessUrlInput.value = s.url;
    if (s.token) harnessTokenInput.value = s.token;
    if (s.mode) scanModeSelect.value = s.mode;
    if (s.scope) scanScopeInput.value = s.scope;
  });

  function currentHarnessSettings() {
    return {
      url: harnessUrlInput.value.trim(),
      token: harnessTokenInput.value.trim(),
      mode: scanModeSelect.value,
      scope: scanScopeInput.value,
    };
  }

  saveHarnessButton.addEventListener("click", function () {
    chrome.storage.local.set({ harnessSettings: currentHarnessSettings() }, function () {
      harnessStatus.textContent = "Settings saved.";
      harnessStatus.style.color = "#2e7d32";
    });
  });

  sendToHarnessButton.addEventListener("click", function () {
    const settings = currentHarnessSettings();
    if (!settings.url || !settings.token) {
      harnessStatus.textContent = "Set the Server URL and Token first.";
      harnessStatus.style.color = "#c62828";
      return;
    }
    if (settings.mode === "active" && !settings.scope.trim()) {
      harnessStatus.textContent = "Active scans need at least one in-scope target.";
      harnessStatus.style.color = "#c62828";
      return;
    }
    chrome.storage.local.set({ harnessSettings: settings });
    sendToHarnessButton.disabled = true;
    const original = sendToHarnessButton.innerHTML;
    sendToHarnessButton.innerHTML = "Sending...";
    harnessStatus.style.color = "#555";
    harnessStatus.textContent = "Uploading capture and starting scan...";
    chrome.runtime.sendMessage({ action: "sendToHarness", settings }, function (response) {
      sendToHarnessButton.disabled = false;
      sendToHarnessButton.innerHTML = original;
      if (chrome.runtime.lastError || !response || response.status === "error") {
        const err = (response && response.error) || (chrome.runtime.lastError && chrome.runtime.lastError.message) || "unknown error";
        harnessStatus.textContent = "Error: " + err;
        harnessStatus.style.color = "#c62828";
        return;
      }
      harnessStatus.innerHTML =
        "Scan started (" + response.mode + "). Scan ID: <code>" + response.scanId +
        "</code>. Report will appear in harness\\data\\reports.";
      harnessStatus.style.color = "#2e7d32";
    });
  });

  function setHarnessSendEnabled(requestCount) {
    if (sendToHarnessButton) sendToHarnessButton.disabled = requestCount === 0;
  }

  // Load last capture time from storage
  chrome.storage.local.get(["lastCaptureTime"], function (result) {
    if (result.lastCaptureTime) {
      lastCaptureSpan.textContent = new Date(
        result.lastCaptureTime
      ).toLocaleString();
    }
  });

  // Check current capture status
  chrome.runtime.sendMessage(
    { action: "getCaptureStatus" },
    function (response) {
      if (chrome.runtime.lastError) {
        console.error(
          "Error getting capture status:",
          chrome.runtime.lastError
        );
        // Set default values if communication fails
        updateUIState(false, 0);
        return;
      }

      // Handle extension not ready state
      if (response && response.status === "not_ready") {
        console.log("Extension still initializing, will retry...");
        showInitializingMessage();
        // Retry after a short delay
        setTimeout(() => {
          chrome.runtime.sendMessage(
            { action: "getCaptureStatus" },
            function (retryResponse) {
              if (retryResponse && retryResponse.status !== "not_ready") {
                hideInitializingMessage();
                updateUIState(
                  retryResponse.isCapturing,
                  retryResponse.requestCount
                );
                if (retryResponse.cloudStats) {
                  updateCloudStats(retryResponse.cloudStats);
                }
              } else {
                console.log("Extension still not ready after retry");
              }
            }
          );
        }, 2000);
        return;
      }

      if (response) {
        updateUIState(response.isCapturing, response.requestCount);
        if (response.cloudStats) {
          updateCloudStats(response.cloudStats);
        }
      }
    }
  );

  function updateUIState(isCapturing, requestCount) {
    startButton.disabled = isCapturing;
    stopButton.disabled = !isCapturing;
    downloadCategorizedButton.disabled = requestCount === 0;
    setHarnessSendEnabled(requestCount || 0);

    // Update status text and dot
    if (isCapturing) {
      statusDiv.textContent = "Capturing...";
      statusDot.className = "status-dot active";
    } else {
      statusDiv.textContent = "Not Capturing";
      statusDot.className = "status-dot inactive";
    }

    requestCountSpan.textContent = requestCount || 0;
  }

  function showInitializingMessage() {
    statusDiv.textContent = "Initializing extension...";
    statusDot.className = "status-dot loading";
    startButton.disabled = true;
    stopButton.disabled = true;
    downloadCategorizedButton.disabled = true;
  }

  function hideInitializingMessage() {
    // UI will be updated by updateUIState called after this
  }

  function updateCloudStats(stats) {
    if (!stats) return;

    cloudCountSpan.textContent = stats.cloudRequests || 0;
    cloudPercentageSpan.textContent = stats.cloudPercentage + "%" || "0%";

    if (stats.topProvider) {
      topProviderDiv.style.display = "block";
      const providerName = topProviderDiv.querySelector(".provider-name");
      const providerServices =
        topProviderDiv.querySelector(".provider-services");

      providerName.textContent = `Top Provider: ${stats.topProvider.name} (${stats.topProvider.count} requests)`;
      providerServices.textContent = `Services: ${
        stats.topProvider.services.join(", ") || "Unknown"
      }`;
    } else {
      topProviderDiv.style.display = "none";
    }
  }

  startButton.addEventListener("click", function () {
    chrome.runtime.sendMessage({ action: "startCapture" }, function (response) {
      if (chrome.runtime.lastError) {
        console.error("Error starting capture:", chrome.runtime.lastError);
        return;
      }

      if (response) {
        if (response.status === "initializing") {
          showInitializingMessage();
          return;
        }

        if (response.status === "not_ready") {
          showInitializingMessage();
          setTimeout(() => {
            hideInitializingMessage();
            updateUIState(false, 0);
          }, 3000);
          return;
        }

        if (response.status === "started") {
          updateUIState(true, 0);
        }
      }
    });
  });

  stopButton.addEventListener("click", function () {
    chrome.runtime.sendMessage({ action: "stopCapture" }, function (response) {
      if (chrome.runtime.lastError) {
        console.error("Error stopping capture:", chrome.runtime.lastError);
        return;
      }
      if (response && response.status === "stopped") {
        // Get the current request count before updating UI
        chrome.runtime.sendMessage(
          { action: "getCaptureStatus" },
          function (statusResponse) {
            if (chrome.runtime.lastError) {
              console.error(
                "Error getting status after stop:",
                chrome.runtime.lastError
              );
              return;
            }
            if (statusResponse) {
              updateUIState(false, statusResponse.requestCount);
              lastCaptureSpan.textContent = new Date().toLocaleString();
              chrome.storage.local.set({
                lastCaptureTime: new Date().toISOString(),
              });
            }
          }
        );
      }
    });
  });

  downloadCategorizedButton.addEventListener("click", function () {
    const filename =
      filenameInput.value.trim() ||
      "capture_" + new Date().toISOString().replace(/[:.]/g, "-");

    // Show loading state
    downloadCategorizedButton.disabled = true;
    downloadCategorizedButton.innerHTML =
      '<span class="loading"></span> Downloading 17 files...';

    chrome.runtime.sendMessage(
      {
        action: "downloadCategorized",
        filename: filename,
      },
      function (response) {
        if (chrome.runtime.lastError) {
          console.error("Error downloading categorized files:", chrome.runtime.lastError);
        }
        // Reset button state after a longer delay (multiple files)
        setTimeout(() => {
          downloadCategorizedButton.disabled = false;
          downloadCategorizedButton.innerHTML = "Download Categorized Files (AI Ready)";
        }, 3000);
      }
    );
  });

  goBackButton.addEventListener("click", function () {
    // Open aicybershield.tech in a new tab
    chrome.tabs.create({ url: "https://aicybershield.tech" });
  });

  // Listen for request count updates
  chrome.runtime.onMessage.addListener((message) => {
    if (message.action === "updateRequestCount") {
      requestCountSpan.textContent = message.count;
      downloadCategorizedButton.disabled = message.count === 0;
      setHarnessSendEnabled(message.count);
    }

    if (message.action === "captureStatusChanged") {
      hideInitializingMessage();
      updateUIState(message.isCapturing, message.requestCount || 0);
    }

    if (message.action === "updateCloudDetections") {
      updateCloudStats(message.stats);
    }

    if (message.action === "downloadError") {
      // Reset button state
      downloadCategorizedButton.disabled = false;
      downloadCategorizedButton.innerHTML = "Download Categorized Files (AI Ready)";

      // Show error message
      showMessage(`Download Error: ${message.error}`, "error");
    }
  });

  // Helper function to show messages
  function showMessage(text, type) {
    // Remove any existing messages
    const existingMessage = document.querySelector(".message");
    if (existingMessage) {
      existingMessage.remove();
    }

    // Create new message
    const message = document.createElement("div");
    message.className = `message ${type}`;
    message.textContent = text;

    // Insert after the download section
    const downloadSection = document.querySelector(".download-section");
    downloadSection.appendChild(message);

    // Remove message after 3 seconds
    setTimeout(() => {
      if (message.parentNode) {
        message.remove();
      }
    }, 3000);
  }
});
