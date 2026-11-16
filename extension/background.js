// Cloud detector will be loaded via importScripts at the top level
// Import cloud detector script
try {
  importScripts("cloud-detector.js");
  console.log("Cloud detector script imported successfully");
} catch (error) {
  console.error("Failed to import cloud detector:", error);
}

console.log("Background script starting...");

// Extension initialization state
let isExtensionReady = false;
let pendingCaptureStart = false;

let capturedRequests = [];
let isCapturing = false;
let detectedVulnerabilities = [];
let cloudDetections = []; // New: Store cloud provider detections
let currentSession = {
  sessionId: null,
  targetUrl: null,
  cookies: {},
  requests: [],
  webStorage: {},
  domAnalysis: {},
  debuggerAttached: false,
};


const FILTERED_TYPES = ["xmlhttprequest", "fetch"];
const IGNORED_PATTERNS = [".png", ".jpg", ".gif", ".css", ".js", "font", "svg"];

// Enhanced data collection storage with comprehensive classification
// SINGLE SOURCE OF TRUTH: capturedRequests contains everything
let enhancedData = {
  networkTraffic: [],
  webStorage: {},
  domVulnerabilities: [],
  securityHeaders: {},
  sensitiveData: [],
  cloudDetections: [],
  
  // Classification indices (references to capturedRequests by index)
  classifications: {
    byCloudProvider: {}, // { aws: [0, 5, 12], azure: [3, 8] } - indices
    byVulnerabilityType: {}, // { clickjacking: [1, 4] } - indices
    bySecurityLevel: { critical: [], high: [], medium: [], low: [], info: [] },
    byEndpointType: { api: [], authentication: [], payment: [], user: [], static: [], other: [] },
    byDataSensitivity: { highlyConfidential: [], confidential: [], internal: [], public: [] },
    byProtocol: { https: [], http: [], wss: [], ws: [], other: [] },
    byRequestType: { GET: [], POST: [], PUT: [], DELETE: [], PATCH: [], OPTIONS: [], HEAD: [], other: [] },
    byContentType: { json: [], html: [], xml: [], formData: [], binary: [], text: [], other: [] },
    uncategorized: [], // Indices of requests that didn't fit specific categories
  }
};

// Store request data for response matching
let requestData = new Map();
let responseData = new Map();

// Map to temporarily store request headers from onBeforeSendHeaders
let requestHeadersMap = new Map();

// Sensitive keywords and static file extension list for filtering
const STATIC_EXTENSIONS = [
  ".css",
  ".js",
  ".png",
  ".jpg",
  ".jpeg",
  ".webp",
  ".svg",
  ".ico",
  ".woff",
  ".woff2",
  ".ttf",
  ".map",
  ".eot",
  ".otf",
];

const SENSITIVE_KEYWORDS = [
  "token",
  "auth",
  "session",
  "secure",
  "userid",
  "user_id",
  "account",
  "fileid",
  "download",
  "jwt",
  "access",
  "secret",
];

function getPathAndQuery(url) {
  try {
    const u = new URL(url);
    return { path: u.pathname, query: u.search };
  } catch (e) {
    return { path: url, query: "" };
  }
}

function getExtensionFromUrl(url) {
  try {
    const pathname = new URL(url).pathname || "";
    const idx = pathname.lastIndexOf(".");
    if (idx === -1) return "";
    return pathname.substring(idx).toLowerCase();
  } catch (e) {
    // fallback: try to parse string
    const parts = url.split(/[?#]/)[0].split("/");
    const last = parts[parts.length - 1] || "";
    const idx = last.lastIndexOf(".");
    return idx === -1 ? "" : last.substring(idx).toLowerCase();
  }
}

// Helper function to hash strings for deduplication
function hashString(str) {
  if (!str) return '';
  let hash = 0;
  const s = String(str);
  for (let i = 0; i < s.length; i++) {
    const char = s.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return hash.toString(36);
}

// Filter headers to keep only security-relevant ones
// CRITICAL: This function preserves all headers needed for security testing
function filterSecurityHeaders(headers) {
  if (!headers || !Array.isArray(headers)) return [];
  
  const SECURITY_HEADER_NAMES = [
    // Authentication & Authorization
    'authorization', 'cookie', 'set-cookie', 'x-api-key', 'x-auth-token', 
    'x-api-token', 'bearer', 'token', 'access-token', 'refresh-token',
    'x-access-token', 'x-refresh-token', 'jwt', 'x-jwt',
    
    // CSRF Protection
    'x-csrf-token', 'x-csrftoken', 'csrf-token', 'csrf', 'x-csrf',
    'x-xsrf-token', 'xsrf-token', 'x-xsrf',
    
    // Request/Response Content
    'content-type', 'accept', 'content-length', 'content-encoding',
    
    // Security Response Headers (CRITICAL for vulnerability detection)
    'x-frame-options', 'content-security-policy', 'strict-transport-security',
    'x-content-type-options', 'x-xss-protection', 'referrer-policy',
    'permissions-policy', 'public-key-pins', 'x-permitted-cross-domain-policies',
    
    // CORS Headers (important for security testing)
    'origin', 'access-control-allow-origin', 'access-control-allow-credentials',
    'access-control-allow-methods', 'access-control-allow-headers',
    'access-control-expose-headers', 'access-control-max-age',
    
    // Additional Security Headers
    'x-requested-with', 'x-request-id', 'x-correlation-id',
    'www-authenticate', 'proxy-authenticate', 'x-forwarded-for',
    'x-real-ip', 'host'
  ];
  
  return headers.filter(h => {
    if (!h || !h.name) return false;
    const name = h.name.toLowerCase();
    // Keep security-relevant headers
    return SECURITY_HEADER_NAMES.some(sh => name.includes(sh));
  });
}

// Check if request is a static resource (for export filtering)
function isStaticResource(req) {
  if (!req || !req.url) return false;
  
  // Check by extension
  const ext = getExtensionFromUrl(req.url);
  if (ext && STATIC_EXTENSIONS.includes(ext)) {
    return true;
  }
  
  // Check by type
  if (req.type === 'stylesheet' || req.type === 'image' || req.type === 'font' || req.type === 'media') {
    return true;
  }
  
  // Check by URL pattern (static CDN patterns)
  const staticPatterns = [
    '/static/', '/assets/', '/css/', '/js/', '/images/', '/img/',
    '/fonts/', '/media/', '.min.js', '.min.css', '.bundle.js'
  ];
  if (staticPatterns.some(pattern => req.url.toLowerCase().includes(pattern))) {
    return true;
  }
  
  return false;
}

function looksLikeBase64Token(value) {
  if (!value || typeof value !== "string") return false;
  const trimmed = value.replace(/\s+/g, "");
  // base64-like: letters+digits+/= length > 30
  if (/^[A-Za-z0-9+/=]{30,}$/.test(trimmed)) return true;
  // hex-like: length > 24
  if (/^[A-Fa-f0-9]{24,}$/.test(trimmed)) return true;
  return false;
}

function urlContainsSensitiveKeywordOrOpaqueToken(url) {
  const { path, query } = getPathAndQuery(url);
  const combined = `${path} ${query}`.toLowerCase();
  // Check keywords first
  for (const kw of SENSITIVE_KEYWORDS) {
    if (combined.includes(kw)) return true;
  }

  // Check path segments and query param values for opaque tokens
  try {
    const u = new URL(url);
    // Check path segments
    const segs = u.pathname.split("/").filter(Boolean);
    for (const s of segs) if (looksLikeBase64Token(s)) return true;

    // Check query params
    for (const [k, v] of u.searchParams.entries()) {
      if (looksLikeBase64Token(k) || looksLikeBase64Token(v)) return true;
    }
  } catch (e) {
    // fallback: check whole string
    if (looksLikeBase64Token(url)) return true;
  }

  return false;
}

function headerListHasSensitive(headers) {
  if (!headers || !Array.isArray(headers)) return false;
  for (const h of headers) {
    const name = (h.name || "").toLowerCase();
    const value = h.value || "";
    if (name === "authorization" || name === "cookie" || name === "x-api-key") return true;
    if (looksLikeBase64Token(value)) return true;
  }
  return false;
}

function contentTypeMatchesExtension(contentType, ext) {
  if (!contentType || !ext) return false;
  contentType = contentType.toLowerCase();
  switch (ext) {
    case ".css":
      return contentType.includes("text/css");
    case ".js":
      return (
        contentType.includes("application/javascript") ||
        contentType.includes("text/javascript")
      );
    case ".png":
    case ".jpg":
    case ".jpeg":
    case ".webp":
    case ".svg":
    case ".ico":
      return contentType.startsWith("image/") || contentType.includes("svg+xml");
    case ".woff":
    case ".woff2":
    case ".ttf":
    case ".eot":
    case ".otf":
      return contentType.includes("font") || contentType.includes("application/font");
    case ".map":
      return contentType.includes("application/json") || contentType.includes("text/javascript");
    default:
      return false;
  }
}

// Should we ignore this request based on static-file heuristics and the rules provided?
function shouldIgnoreStaticCapture(request, response) {
  // request: { method, url, requestHeaders? }
  // response: { status, contentType }
  const ext = getExtensionFromUrl(request.url);
  if (!STATIC_EXTENSIONS.includes(ext)) return false;

  // If URL contains keywords/opaque tokens -> candidate => do NOT ignore
  if (urlContainsSensitiveKeywordOrOpaqueToken(request.url)) return false;

  // If request has sensitive headers -> do NOT ignore
  if (request.requestHeaders && headerListHasSensitive(request.requestHeaders)) return false;

  // If method is HEAD -> treat as don't capture when static
  if (request.method && request.method.toUpperCase() === "HEAD") return true;

  // If we have response info, apply additional rules
  if (response) {
    const status = response.status;
    const contentType = response.contentType || response.mimeType || "";

    // If response status is 401/403/500 -> store it (do not ignore)
    if ([401, 403, 500].includes(status)) return false;

    // If content-type mismatches extension, store it
    if (!contentTypeMatchesExtension(contentType, ext)) return false;

    // If status is 200 and contentType matches expected, ignore (do not capture)
    if (status === 200 && contentTypeMatchesExtension(contentType, ext)) return true;
  }

  // Default: do not ignore
  return false;
}

// Initialize cloud detector
let cloudDetector;

// Initialize cloud detector for Manifest V3 service worker
function initializeCloudDetector() {
  try {
    // CloudProviderDetector should be available globally after importScripts
    if (typeof CloudProviderDetector !== "undefined") {
      cloudDetector = new CloudProviderDetector();
      console.log("Cloud detector initialized successfully");
    } else {
      throw new Error("CloudProviderDetector not found");
    }
  } catch (error) {
    console.error("Failed to initialize cloud detector:", error);
    // Fallback: create a dummy detector that returns null
    cloudDetector = {
      analyzeRequest: () => ({
        summary: { isCloudService: false },
        cloudProviders: [],
      }),
      getStatistics: () => ({
        totalRequests: 0,
        cloudRequests: 0,
        providers: {},
        cloudPercentage: 0,
      }),
    };
  }
}

// Initialize extension properly
async function initializeExtension() {
  try {
    console.log("Initializing extension...");

    // Initialize cloud detector
    initializeCloudDetector();

    // Load saved state from storage
    try {
      const result = await chrome.storage.local.get([
        "capturedRequests",
        "currentSession",
        "detectedVulnerabilities",
        "cloudDetections",
        "enhancedData",
        "isCapturing",
      ]);

      if (result.capturedRequests) {
        capturedRequests = result.capturedRequests;
      }
      if (result.currentSession) {
        currentSession = result.currentSession;
      }
      if (result.detectedVulnerabilities) {
        detectedVulnerabilities = result.detectedVulnerabilities;
      }
      if (result.cloudDetections) {
        cloudDetections = result.cloudDetections;
      }
      if (result.enhancedData) {
        enhancedData = result.enhancedData;
      }
      if (result.isCapturing) {
        isCapturing = result.isCapturing;
      }

      console.log("Restored extension state from storage");
    } catch (error) {
      console.log(
        "No previous state to restore or error loading state:",
        error
      );
    }

    isExtensionReady = true;
    console.log("Extension initialized successfully");

    if (!isCapturing && pendingCaptureStart) {
      console.log("Processing queued start capture request after initialization");
      pendingCaptureStart = false;
      startCapture();
    }
    
    // Restore capture state if it was previously capturing
    // Add small delay to ensure all initialization is complete
    if (isCapturing) {
      console.log("Restoring capture state after extension initialization");
      // Use setTimeout to ensure extension is fully ready before starting capture
      setTimeout(() => {
        if (isExtensionReady && cloudDetector) {
          startCapture();
        } else {
          console.warn("Extension not fully ready, delaying capture start");
          // Retry after a longer delay
          setTimeout(() => {
            if (isCapturing) {
              startCapture();
            }
          }, 500);
        }
      }, 100);
    }
  } catch (error) {
    console.error("Failed to initialize extension:", error);
    isExtensionReady = true; // Set to true even on error to prevent blocking
  }
}

// Handle extension installation and startup
chrome.runtime.onInstalled.addListener((details) => {
  console.log("Extension installed/updated:", details.reason);

  if (details.reason === "install") {
    console.log("First time installation - setting up extension");
    // Clear any existing data on fresh install
    chrome.storage.local.clear();
  } else if (details.reason === "update") {
    console.log(
      "Extension updated to version:",
      chrome.runtime.getManifest().version
    );
  }

  initializeExtension();
});

// Handle service worker startup
chrome.runtime.onStartup.addListener(() => {
  console.log("Extension startup detected");
  initializeExtension();
});

// Initialize immediately if service worker is already running
initializeExtension();

// Helper functions for enhanced network capture
function parseUrl(url) {
  try {
    const urlObj = new URL(url);
    return {
      protocol: urlObj.protocol,
      hostname: urlObj.hostname,
      port: urlObj.port,
      pathname: urlObj.pathname,
      search: urlObj.search,
      hash: urlObj.hash,
      searchParams: Object.fromEntries(urlObj.searchParams.entries()),
    };
  } catch (e) {
    return { error: "Invalid URL" };
  }
}

function extractSecurityHeaders(headers) {
  if (!headers) return {};

  const securityHeaders = {};
  const importantHeaders = [
    "authorization",
    "cookie",
    "x-csrf-token",
    "x-xsrf-token",
    "x-api-key",
    "x-auth-token",
    "x-requested-with",
    "content-type",
    "content-length",
    "user-agent",
    "referer",
    "origin",
    "host",
  ];

  importantHeaders.forEach((header) => {
    const value =
      headers[header] ||
      headers[header.charAt(0).toUpperCase() + header.slice(1)];
    if (value) {
      securityHeaders[header] = value;
    }
  });

  return securityHeaders;
}

function calculateRequestSize(request) {
  let size = 0;

  // URL size
  size += request.url ? request.url.length : 0;

  // Headers size
  if (request.headers) {
    Object.entries(request.headers).forEach(([key, value]) => {
      size += key.length + (value ? value.length : 0) + 2; // +2 for ": "
    });
  }

  // Post data size
  if (request.postData) {
    size += request.postData.length;
  }

  return size;
}

function calculateResponseSize(response) {
  let size = 0;

  // Status line
  size += response.status ? response.status.toString().length : 0;
  size += response.statusText ? response.statusText.length : 0;

  // Headers size
  if (response.headers) {
    Object.entries(response.headers).forEach(([key, value]) => {
      size += key.length + (value ? value.length : 0) + 2; // +2 for ": "
    });
  }

  // Body size
  if (response.body) {
    size += response.body.length;
  }

  return size;
}

// ============================================================================
// COMPREHENSIVE CLASSIFICATION SYSTEM
// ============================================================================

/**
 * Classify request by endpoint type
 */
function classifyEndpointType(url, method, headers, requestBody) {
  const urlLower = url.toLowerCase();
  
  // API endpoint patterns
  if (urlLower.includes('/api/') || 
      urlLower.includes('/v1/') || 
      urlLower.includes('/v2/') ||
      urlLower.includes('/graphql') ||
      urlLower.includes('/rest/')) {
    return 'api';
  }
  
  // Authentication endpoints
  if (urlLower.includes('/auth') || 
      urlLower.includes('/login') || 
      urlLower.includes('/signin') ||
      urlLower.includes('/oauth') ||
      urlLower.includes('/sso') ||
      urlLower.includes('/token') ||
      urlLower.includes('/session')) {
    return 'authentication';
  }
  
  // Payment endpoints
  if (urlLower.includes('/payment') || 
      urlLower.includes('/checkout') || 
      urlLower.includes('/billing') ||
      urlLower.includes('/stripe') ||
      urlLower.includes('/paypal') ||
      urlLower.includes('/purchase')) {
    return 'payment';
  }
  
  // User/Profile endpoints
  if (urlLower.includes('/user') || 
      urlLower.includes('/profile') || 
      urlLower.includes('/account') ||
      urlLower.includes('/me')) {
    return 'user';
  }
  
  // Static resources
  if (urlLower.match(/\.(jpg|jpeg|png|gif|svg|ico|css|js|woff|woff2|ttf|eot)$/)) {
    return 'static';
  }
  
  return 'other';
}

/**
 * Classify data sensitivity level
 */
function classifyDataSensitivity(url, method, headers, requestBody, responseHeaders) {
  let sensitivityLevel = 'public';
  let reasons = [];
  
  const urlLower = url.toLowerCase();
  const bodyString = JSON.stringify(requestBody || {}).toLowerCase();
  const headersString = JSON.stringify(headers || {}).toLowerCase();
  
  // Highly Confidential patterns
  const highlyConfidentialPatterns = [
    /password/i,
    /credit[_-]?card/i,
    /ssn/i,
    /social[_-]?security/i,
    /private[_-]?key/i,
    /secret[_-]?key/i,
    /api[_-]?secret/i,
    /bearer\s+[a-zA-Z0-9]/i,
  ];
  
  for (const pattern of highlyConfidentialPatterns) {
    if (pattern.test(urlLower) || pattern.test(bodyString) || pattern.test(headersString)) {
      sensitivityLevel = 'highlyConfidential';
      reasons.push(`Contains ${pattern.source}`);
      break;
    }
  }
  
  // Confidential patterns
  if (sensitivityLevel !== 'highlyConfidential') {
    const confidentialPatterns = [
      /token/i,
      /api[_-]?key/i,
      /session/i,
      /auth/i,
      /email/i,
      /phone/i,
      /address/i,
    ];
    
    for (const pattern of confidentialPatterns) {
      if (pattern.test(urlLower) || pattern.test(bodyString) || pattern.test(headersString)) {
        sensitivityLevel = 'confidential';
        reasons.push(`Contains ${pattern.source}`);
        break;
      }
    }
  }
  
  // Internal patterns
  if (sensitivityLevel === 'public') {
    if (urlLower.includes('/internal') || 
        urlLower.includes('/admin') ||
        headers?.authorization ||
        headers?.Authorization) {
      sensitivityLevel = 'internal';
      reasons.push('Internal or authenticated endpoint');
    }
  }
  
  return { level: sensitivityLevel, reasons };
}

/**
 * Classify security level based on vulnerabilities
 */
function classifySecurityLevel(vulnerabilities) {
  if (!vulnerabilities || vulnerabilities.length === 0) {
    return 'info';
  }
  
  const severities = vulnerabilities.map(v => v.severity);
  
  if (severities.includes('CRITICAL')) return 'critical';
  if (severities.includes('HIGH')) return 'high';
  if (severities.includes('MEDIUM')) return 'medium';
  if (severities.includes('LOW')) return 'low';
  
  return 'info';
}

/**
 * Classify content type
 */
function classifyContentType(headers, url) {
  const contentType = headers?.['content-type'] || headers?.['Content-Type'] || '';
  
  if (contentType.includes('application/json')) return 'json';
  if (contentType.includes('text/html')) return 'html';
  if (contentType.includes('application/xml') || contentType.includes('text/xml')) return 'xml';
  if (contentType.includes('multipart/form-data') || contentType.includes('application/x-www-form-urlencoded')) return 'formData';
  if (contentType.includes('text/')) return 'text';
  if (contentType.includes('image/') || contentType.includes('video/') || contentType.includes('audio/')) return 'binary';
  
  // Fallback to URL extension
  if (url.match(/\.(jpg|jpeg|png|gif|svg|ico|mp4|mp3|pdf|zip)$/i)) return 'binary';
  
  return 'text';
}

/**
 * Main classification function - applies all classifications to a request
 */
function classifyRequest(completeRequest) {
  const url = completeRequest.url || '';
  const method = completeRequest.method || 'GET';
  const headers = completeRequest.headers || {};
  const requestBody = completeRequest.requestBody || completeRequest.postData;
  const responseHeaders = completeRequest.response?.headers || {};
  const vulnerabilities = completeRequest.vulnerabilities || [];
  
  // Parse URL protocol
  let protocol = 'http';
  try {
    const urlObj = new URL(url);
    protocol = urlObj.protocol.replace(':', '');
  } catch (e) {
    // Invalid URL
  }
  
  const classification = {
    timestamp: Date.now(),
    requestId: completeRequest.requestId,
    url: url,
    
    // Cloud provider classification
    cloudProvider: null,
    
    // Endpoint type
    endpointType: classifyEndpointType(url, method, headers, requestBody),
    
    // Data sensitivity
    dataSensitivity: classifyDataSensitivity(url, method, headers, requestBody, responseHeaders),
    
    // Security level
    securityLevel: classifySecurityLevel(vulnerabilities),
    
    // Protocol
    protocol: protocol,
    
    // Request method
    requestMethod: method.toUpperCase(),
    
    // Content type
    contentType: classifyContentType(responseHeaders, url),
    
    // Store vulnerability info (not the full request to avoid circular reference)
    vulnerabilities: vulnerabilities,
  };
  
  // Add cloud provider classification if available
  if (cloudDetector) {
    const cloudDetection = cloudDetector.detectFromUrl(url);
    if (cloudDetection && cloudDetection.summary?.isCloudService) {
      classification.cloudProvider = {
        provider: cloudDetection.summary.primaryProvider || 'unknown',
        service: cloudDetection.summary.service?.name || 'unknown',
        confidence: cloudDetection.summary.confidence || 0,
      };
    }
  }
  
  return classification;
}

/**
 * Add request to classification categories
 * EFFICIENT: Stores classification metadata in the request itself
 * Uses index-based references to avoid data duplication
 */
function addToClassifications(classification) {
  // Find the request index in capturedRequests
  const requestIndex = capturedRequests.length - 1; // Just added
  
  // Store classification metadata directly in the request object
  if (requestIndex >= 0 && capturedRequests[requestIndex]) {
    capturedRequests[requestIndex].classification = classification;
  }
  
  // Initialize category arrays if needed
  if (!enhancedData.classifications.byCloudProvider) {
    enhancedData.classifications.byCloudProvider = {};
  }
  if (!enhancedData.classifications.byVulnerabilityType) {
    enhancedData.classifications.byVulnerabilityType = {};
  }
  
  // Add index to cloud provider classification
  if (classification.cloudProvider) {
    const provider = classification.cloudProvider.provider;
    if (!enhancedData.classifications.byCloudProvider[provider]) {
      enhancedData.classifications.byCloudProvider[provider] = [];
    }
    enhancedData.classifications.byCloudProvider[provider].push(requestIndex);
  }
  
  // Add index to vulnerability type classification
  if (classification.vulnerabilities && classification.vulnerabilities.length > 0) {
    classification.vulnerabilities.forEach(vuln => {
      const vulnType = vuln.type || 'unknown';
      if (!enhancedData.classifications.byVulnerabilityType[vulnType]) {
        enhancedData.classifications.byVulnerabilityType[vulnType] = [];
      }
      enhancedData.classifications.byVulnerabilityType[vulnType].push(requestIndex);
    });
  }
  
  // Add index to security level classification
  const secLevel = classification.securityLevel || 'info';
  enhancedData.classifications.bySecurityLevel[secLevel].push(requestIndex);
  
  // Add index to endpoint type classification
  const endpointType = classification.endpointType || 'other';
  enhancedData.classifications.byEndpointType[endpointType].push(requestIndex);
  
  // Add index to data sensitivity classification
  const sensitivity = classification.dataSensitivity?.level || 'public';
  enhancedData.classifications.byDataSensitivity[sensitivity].push(requestIndex);
  
  // Add index to protocol classification
  const protocol = classification.protocol || 'other';
  if (enhancedData.classifications.byProtocol[protocol]) {
    enhancedData.classifications.byProtocol[protocol].push(requestIndex);
  } else {
    enhancedData.classifications.byProtocol.other.push(requestIndex);
  }
  
  // Add index to request type classification
  const method = classification.requestMethod || 'other';
  if (enhancedData.classifications.byRequestType[method]) {
    enhancedData.classifications.byRequestType[method].push(requestIndex);
  } else {
    enhancedData.classifications.byRequestType.other.push(requestIndex);
  }
  
  // Add index to content type classification
  const contentType = classification.contentType || 'other';
  if (enhancedData.classifications.byContentType[contentType]) {
    enhancedData.classifications.byContentType[contentType].push(requestIndex);
  } else {
    enhancedData.classifications.byContentType.other.push(requestIndex);
  }
  
  // Track uncategorized if needed
  if (!classification.cloudProvider && endpointType === 'other') {
    enhancedData.classifications.uncategorized.push(requestIndex);
  }
}

/**
 * Get classification statistics
 * Includes counts from ALL classifications (nothing lost)
 */
/**
 * Get classification statistics
 * Returns counts only (not full objects) for efficiency
 */
function getClassificationStatistics() {
  return {
    // Total counts
    totalRequests: capturedRequests.length,
    totalVulnerabilities: detectedVulnerabilities.length,
    
    cloudProviders: Object.keys(enhancedData.classifications.byCloudProvider).map(provider => ({
      provider,
      count: enhancedData.classifications.byCloudProvider[provider].length
    })),
    
    vulnerabilities: Object.keys(enhancedData.classifications.byVulnerabilityType).map(type => ({
      type,
      count: enhancedData.classifications.byVulnerabilityType[type].length
    })),
    
    securityLevels: Object.keys(enhancedData.classifications.bySecurityLevel).map(level => ({
      level,
      count: enhancedData.classifications.bySecurityLevel[level].length
    })),
    
    endpointTypes: Object.keys(enhancedData.classifications.byEndpointType).map(type => ({
      type,
      count: enhancedData.classifications.byEndpointType[type].length
    })),
    
    dataSensitivity: Object.keys(enhancedData.classifications.byDataSensitivity).map(level => ({
      level,
      count: enhancedData.classifications.byDataSensitivity[level].length
    })),
    
    protocols: Object.keys(enhancedData.classifications.byProtocol).map(proto => ({
      protocol: proto,
      count: enhancedData.classifications.byProtocol[proto].length
    })),
    
    requestMethods: Object.keys(enhancedData.classifications.byRequestType).map(method => ({
      method,
      count: enhancedData.classifications.byRequestType[method].length
    })),
    
    contentTypes: Object.keys(enhancedData.classifications.byContentType).map(type => ({
      type,
      count: enhancedData.classifications.byContentType[type].length
    })),
    
    // Special categories
    uncategorized: {
      count: enhancedData.classifications.uncategorized?.length || 0
    }
  };
}

// Helper function to safely send messages to popup
// Helper function to safely send messages to popup
function safeSendMessage(message) {
  try {
    chrome.runtime.sendMessage(message, (response) => {
      // Check for errors and ignore them if popup is not open
      if (chrome.runtime.lastError) {
        // Silently ignore "receiving end does not exist" errors
        console.log("Message not delivered (popup may be closed):", message.action);
      }
    });
  } catch (error) {
    // Ignore errors when popup is not open
    console.log("Popup not open, skipping message send:", message.action);
  }
}

// Helper function to convert bytes to readable text
function bytesToText(bytes) {
  if (!bytes || bytes.length === 0) return "";

  try {
    // Try to decode as UTF-8 text
    const text = new TextDecoder("utf-8").decode(new Uint8Array(bytes));

    // Check if the text is readable (contains printable characters)
    const printableRatio =
      text
        .split("")
        .filter(
          (char) =>
            (char.charCodeAt(0) >= 32 && char.charCodeAt(0) <= 126) ||
            char.charCodeAt(0) >= 160
        ).length / text.length;

    if (printableRatio > 0.7) {
      return text;
    }
  } catch (error) {
    // UTF-8 decoding failed
  }

  // Try to decode as base64
  try {
    const base64 = btoa(String.fromCharCode.apply(null, bytes));
    return `[Base64] ${base64}`;
  } catch (e) {
    // Base64 encoding failed
  }

  // Return as hex if all else fails
  return `[Hex] ${bytes.map((b) => b.toString(16).padStart(2, "0")).join(" ")}`;
}

// Helper function to process request body
function processRequestBody(requestBody) {
  if (!requestBody) return null;

  try {
    const processed = {};

    // Process raw data - ONLY store decoded text, skip bytes array
    if (requestBody.raw) {
      processed.raw = requestBody.raw.map((r, index) => {
        try {
          const bytes = Array.from(new Uint8Array(r.bytes));
          return {
            index: index,
            // Skip bytes array - only keep decoded text
            text: bytesToText(bytes),
            size: bytes.length,
          };
        } catch (error) {
          console.error("Error processing raw data:", error);
          return {
            index: index,
            text: "[Error processing data]",
            size: 0,
          };
        }
      });
    }

    // Process form data
    if (requestBody.formData) {
      processed.formData = {};
      for (const [key, values] of Object.entries(requestBody.formData)) {
        processed.formData[key] = values.map((value) => {
          try {
            // Try to detect if value is base64 encoded
            if (typeof value === "string" && value.length > 0) {
              const decoded = atob(value);
              return {
                original: value,
                decoded: decoded,
                isBase64: true,
              };
            }
          } catch (e) {
            // Not base64, return as is
          }
          return {
            original: value,
            decoded: value,
            isBase64: false,
          };
        });
      }
    }

    return processed;
  } catch (error) {
    console.error("Error processing request body:", error);
    return null;
  }
}

// Enhanced Debugger API Integration for Full Network Traffic Capture
async function attachDebugger(tabId) {
  try {
    // Get tab info first to check if it's a valid target
    const tab = await chrome.tabs.get(tabId);

    // Skip chrome:// URLs and other restricted URLs
    if (
      tab.url.startsWith("chrome://") ||
      tab.url.startsWith("chrome-extension://") ||
      tab.url.startsWith("moz-extension://") ||
      tab.url.startsWith("edge://") ||
      tab.url.startsWith("about:")
    ) {
      console.log("Skipping debugger attachment for restricted URL:", tab.url);
      return;
    }

    // Check if debugger is already attached
    const existingTargets = await chrome.debugger.getTargets();
    const isAlreadyAttached = existingTargets.some(
      (target) => target.tabId === tabId && target.attached
    );

    if (isAlreadyAttached) {
      console.log("Debugger already attached to tab:", tabId);
      currentSession.debuggerAttached = true;
      return; // Already attached, no need to attach again
    }

    // Attempt to attach debugger
    await chrome.debugger.attach({ tabId }, "1.3");
    console.log("Debugger successfully attached to tab:", tabId);

    // Enable comprehensive network monitoring
    await chrome.debugger.sendCommand({ tabId }, "Network.enable", {
      maxTotalBufferSize: 10000000, // 10MB buffer
      maxResourceBufferSize: 5000000, // 5MB per resource
      maxPostDataSize: 5000000, // 5MB post data
    });

    // Enable additional network events
    await chrome.debugger.sendCommand(
      { tabId },
      "Network.setExtraHTTPHeaders",
      {
        headers: {},
      }
    );

    // Enable request interception for more detailed capture
    await chrome.debugger.sendCommand(
      { tabId },
      "Network.setRequestInterception",
      {
        patterns: [
          {
            urlPattern: "*",
            resourceType: "Document",
            interceptionStage: "Request",
          },
        ],
      }
    );

    currentSession.debuggerAttached = true;
    console.log("Enhanced debugger attached to tab:", tabId);

    // Set up debugger event listeners
    chrome.debugger.onEvent.addListener((source, method, params) => {
      if (source.tabId === tabId && isCapturing) {
        handleDebuggerEvent(method, params);
      }
    });
  } catch (error) {
    // Handle specific error cases
    if (error.message && error.message.includes("already attached")) {
      console.log("Debugger already attached (handled):", tabId);
      currentSession.debuggerAttached = true;
    } else if (error.message && error.message.includes("Cannot access")) {
      console.log("Cannot attach debugger to this tab (restricted):", tabId);
      currentSession.debuggerAttached = false;
    } else {
      console.error("Failed to attach debugger:", error.message || error);
      currentSession.debuggerAttached = false;
    }
  }
}

function detachDebugger(tabId) {
  return new Promise((resolve) => {
    try {
      // Check if debugger is actually attached before attempting to detach
      chrome.debugger.getTargets().then((targets) => {
        const isAttached = targets.some(
          (target) => target.tabId === tabId && target.attached
        );

        if (isAttached) {
          chrome.debugger.detach({ tabId }, () => {
            if (chrome.runtime.lastError) {
              console.log("Detach error (ignored):", chrome.runtime.lastError.message);
            } else {
              console.log("Debugger detached from tab:", tabId);
            }
            currentSession.debuggerAttached = false;
            resolve();
          });
        } else {
          currentSession.debuggerAttached = false;
          resolve();
        }
      }).catch((error) => {
        console.log("Error checking debugger targets:", error);
        currentSession.debuggerAttached = false;
        resolve();
      });
    } catch (error) {
      console.error("Failed to detach debugger:", error);
      currentSession.debuggerAttached = false;
      resolve();
    }
  });
}

function handleDebuggerEvent(method, params) {
  switch (method) {
    case "Network.requestWillBeSent":
      handleRequestWillBeSent(params);
      break;
    case "Network.responseReceived":
      handleResponseReceived(params);
      break;
    case "Network.dataReceived":
      handleDataReceived(params);
      break;
    case "Network.loadingFinished":
      handleLoadingFinished(params);
      break;
    case "Network.loadingFailed":
      handleLoadingFailed(params);
      break;
    case "Network.responseReceivedExtraInfo":
      handleResponseExtraInfo(params);
      break;
    case "Network.requestWillBeSentExtraInfo":
      handleRequestExtraInfo(params);
      break;
    case "Network.resourceChangedPriority":
      handleResourcePriorityChange(params);
      break;
    case "Network.signedExchangeReceived":
      handleSignedExchange(params);
      break;
    case "Network.requestIntercepted":
      handleRequestIntercepted(params);
      break;
  }
}

function handleRequestWillBeSent(params) {
  const requestId = params.requestId;
  const request = {
    requestId: requestId,
    url: params.request.url,
    method: params.request.method,
    headers: params.request.headers,
    postData: params.request.postData,
    timestamp: Date.now(),
    type: params.type || "unknown",
    frameId: params.frameId,
    loaderId: params.loaderId,
    documentURL: params.documentURL,
    initiator: params.initiator,
    // Enhanced network tab-like information
    requestSize: calculateRequestSize(params.request),
    hasPostData: !!params.request.postData,
    urlParsed: parseUrl(params.request.url),
    headersCount: params.request.headers
      ? Object.keys(params.request.headers).length
      : 0,
    securityHeaders: extractSecurityHeaders(params.request.headers),
    startTime: Date.now(),
    // Additional metadata
    contentType: params.request.headers
      ? params.request.headers["content-type"] ||
        params.request.headers["Content-Type"]
      : null,
    userAgent: params.request.headers
      ? params.request.headers["user-agent"] ||
        params.request.headers["User-Agent"]
      : null,
    referer: params.request.headers
      ? params.request.headers["referer"] || params.request.headers["Referer"]
      : null,
    origin: params.request.headers
      ? params.request.headers["origin"] || params.request.headers["Origin"]
      : null,
  };

  requestData.set(requestId, request);

  // Add to enhanced data collection
  enhancedData.networkTraffic.push({
    type: "request",
    timestamp: Date.now(),
    data: request,
  });
}

function handleResponseReceived(params) {
  const requestId = params.requestId;
  const response = {
    requestId: requestId,
    url: params.response.url,
    status: params.response.status,
    statusText: params.response.statusText,
    headers: params.response.headers,
    mimeType: params.response.mimeType,
    timestamp: Date.now(),
    type: params.type || "unknown",
    // Enhanced response information
    responseSize: 0, // Will be calculated when body is received
    headersCount: params.response.headers
      ? Object.keys(params.response.headers).length
      : 0,
    securityHeaders: extractSecurityHeaders(params.response.headers),
    // Response metadata
    contentType: params.response.headers
      ? params.response.headers["content-type"] ||
        params.response.headers["Content-Type"]
      : null,
    contentLength: params.response.headers
      ? params.response.headers["content-length"] ||
        params.response.headers["Content-Length"]
      : null,
    server: params.response.headers
      ? params.response.headers["server"] || params.response.headers["Server"]
      : null,
    // Timing information
    responseTime: Date.now(),
  };

  responseData.set(requestId, response);

  // Add to enhanced data collection
  enhancedData.networkTraffic.push({
    type: "response",
    timestamp: Date.now(),
    data: response,
  });
}

function handleDataReceived(params) {
  const requestId = params.requestId;
  const existingData = responseData.get(requestId);

  if (existingData) {
    if (!existingData.body) {
      existingData.body = "";
    }
    existingData.body += params.data;

    // Update response size
    existingData.responseSize = calculateResponseSize(existingData);
    existingData.bodySize = existingData.body.length;
  }
}

function handleLoadingFinished(params) {
  const requestId = params.requestId;
  const request = requestData.get(requestId);
  const response = responseData.get(requestId);

  if (request && response) {
    // Calculate timing information
    const endTime = Date.now();
    const duration = endTime - request.startTime;

    // Combine request and response data with enhanced information
    const completeRequest = {
      ...request,
      response: response,
      timestamp: Date.now(),
      // Network tab-like summary
      summary: {
        method: request.method,
        status: response.status,
        statusText: response.statusText,
        type: request.type,
        url: request.url,
        // Size information
        requestSize: request.requestSize,
        responseSize: response.responseSize,
        bodySize: response.bodySize || 0,
        // Timing information
        duration: duration,
        startTime: request.startTime,
        endTime: endTime,
        // Additional metadata
        hasPostData: request.hasPostData,
        headersCount: request.headersCount,
        responseHeadersCount: response.headersCount,
        mimeType: response.mimeType,
        server: response.server,
      },
      // Enhanced security analysis
      security: {
        isSecure: request.url.startsWith("https://"),
        hasAuthHeaders: !!request.securityHeaders.authorization,
        hasCSRFToken:
          !!request.securityHeaders["x-csrf-token"] ||
          !!request.securityHeaders["x-xsrf-token"],
        contentType: request.contentType,
        userAgent: request.userAgent,
        referer: request.referer,
        origin: request.origin,
      },
      vulnerabilities: [], // Will be populated by vulnerability scan
    };

    // Apply static-file ignore heuristics (CDP captured requests)
    const responseMeta = { status: response.status, contentType: response.contentType || response.mimeType };
    const minimalReq = { method: request.method, url: request.url, requestHeaders: request.headers };
    if (shouldIgnoreStaticCapture(minimalReq, responseMeta)) {
      // skip storing this static/benign resource
      return;
    }

    capturedRequests.push(completeRequest);

    // Run enhanced vulnerability analysis
    runEnhancedVulnerabilityScan(completeRequest);
    
    // Classify the request comprehensively
    const classification = classifyRequest(completeRequest);
    addToClassifications(classification);
    
    // Send classification update to popup
    safeSendMessage({ action: "classificationUpdate", statistics: getClassificationStatistics() });
    
    // Update popup
    safeSendMessage({ action: "updateRequestCount", count: capturedRequests.length });
  }
}

function handleResponseExtraInfo(params) {
  const requestId = params.requestId;
  const response = responseData.get(requestId);

  if (response) {
    response.extraHeaders = params.headers;
  }
}

function handleRequestExtraInfo(params) {
  const requestId = params.requestId;
  const request = requestData.get(requestId);

  if (request) {
    request.extraHeaders = params.headers;
    request.associatedCookies = params.associatedCookies;
    request.connectTiming = params.connectTiming;
  }
}

function handleLoadingFailed(params) {
  const requestId = params.requestId;
  const request = requestData.get(requestId);
  const response = responseData.get(requestId);

  if (request) {
    const failedRequest = {
      ...request,
      response: response,
      error: {
        errorText: params.errorText,
        canceled: params.canceled,
        blockedReason: params.blockedReason,
        type: params.type,
      },
      timestamp: Date.now(),
    };

    capturedRequests.push(failedRequest);

    // Update popup
    safeSendMessage({
      action: "updateRequestCount",
      count: capturedRequests.length,
    });
  }
}

function handleResourcePriorityChange(params) {
  const requestId = params.requestId;
  const request = requestData.get(requestId);

  if (request) {
    request.newPriority = params.newPriority;
    request.timestamp = Date.now();
  }
}

function handleSignedExchange(params) {
  const requestId = params.requestId;
  const request = requestData.get(requestId);

  if (request) {
    request.signedExchange = {
      header: params.header,
      signature: params.signature,
      validityUrl: params.validityUrl,
    };
  }
}

// Handle intercepted requests - CRITICAL for allowing navigation
async function handleRequestIntercepted(params) {
  try {
    // Get the current tab with debugger attached
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      if (!tabs[0] || !currentSession.debuggerAttached) {
        console.warn("No active tab or debugger not attached");
        return;
      }

      const tabId = tabs[0].id;
      
      // Log intercepted request for reconnaissance
      console.log("Intercepted Request:", {
        url: params.request?.url,
        method: params.request?.method,
        resourceType: params.resourceType,
        interceptionId: params.interceptionId,
        timestamp: Date.now(),
      });

      // Store intercepted request data for analysis
      enhancedData.networkTraffic.push({
        type: "intercepted_request",
        timestamp: Date.now(),
        data: {
          interceptionId: params.interceptionId,
          request: params.request,
          resourceType: params.resourceType,
          isNavigationRequest: params.isNavigationRequest,
          frameId: params.frameId,
          responseHeaders: params.responseHeaders,
          responseStatusCode: params.responseStatusCode,
        },
      });

      try {
        // Continue the request without modification
        // For security testing, you can modify headers, body, etc. here
        await chrome.debugger.sendCommand(
          { tabId: tabId },
          "Network.continueInterceptedRequest",
          {
            interceptionId: params.interceptionId,
            // Optional: Modify request here for security testing
            // rawResponse: btoa("HTTP/1.1 200 OK\r\n..."),
            // url: params.request.url,
            // method: params.request.method,
            // postData: params.request.postData,
            // headers: params.request.headers,
          }
        );
        
        console.log("Request continued successfully");
      } catch (error) {
        console.error("Failed to continue intercepted request:", error);
        
        // Try to continue anyway to prevent blocking
        try {
          await chrome.debugger.sendCommand(
            { tabId: tabId },
            "Network.continueInterceptedRequest",
            {
              interceptionId: params.interceptionId,
            }
          );
        } catch (retryError) {
          console.error("Retry failed:", retryError);
        }
      }
    });
  } catch (error) {
    console.error("Error in handleRequestIntercepted:", error);
  }
}

// Web Storage Collection
function collectWebStorage(tabId) {
  chrome.tabs.sendMessage(
    tabId,
    { action: "collectWebStorage" },
    (response) => {
      if (chrome.runtime.lastError) {
        console.log(
          "Note: Could not collect web storage (may be restricted page):",
          chrome.runtime.lastError.message
        );
        // Set empty storage data instead of failing
        enhancedData.webStorage = {
          localStorage: {},
          sessionStorage: {},
          cookies: {},
          error: chrome.runtime.lastError.message,
        };
        currentSession.webStorage = enhancedData.webStorage;
        return;
      }
      if (response && response.success) {
        enhancedData.webStorage = response.data;
        currentSession.webStorage = response.data;
        console.log("Web storage collected:", response.data);
      } else {
        console.log(
          "Web storage collection failed:",
          response?.error || "Unknown error"
        );
        // Set empty storage data
        enhancedData.webStorage = {
          localStorage: {},
          sessionStorage: {},
          cookies: {},
          error: response?.error || "Collection failed",
        };
        currentSession.webStorage = enhancedData.webStorage;
      }
    }
  );
}

// DOM Security Analysis
function analyzeDOMSecurity(tabId) {
  chrome.tabs.sendMessage(
    tabId,
    { action: "analyzeDOMSecurity" },
    (response) => {
      if (chrome.runtime.lastError) {
        console.log(
          "Note: Could not analyze DOM security (may be restricted page):",
          chrome.runtime.lastError.message
        );
        // Set empty DOM analysis instead of failing
        enhancedData.domVulnerabilities = [];
        currentSession.domAnalysis = {
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
          error: chrome.runtime.lastError.message,
        };
        return;
      }
      if (response && response.success) {
        enhancedData.domVulnerabilities = response.vulnerabilities;
        currentSession.domAnalysis = response;
        console.log("DOM analysis completed:", response);
      } else {
        console.log("DOM analysis failed:", response?.error || "Unknown error");
        // Set empty DOM analysis
        enhancedData.domVulnerabilities = [];
        currentSession.domAnalysis = {
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
          error: response?.error || "Analysis failed",
        };
      }
    }
  );
}

// Vulnerability detection functions (existing code)
function detectClickjackingVulnerability(url, headers) {
  const xFrameOptions =
    headers["x-frame-options"] || headers["X-Frame-Options"];
  const contentType = headers["content-type"] || headers["Content-Type"];

  if (!xFrameOptions) {
    return {
      type: "Clickjacking",
      severity: "HIGH",
      description:
        "Missing X-Frame-Options header - page can be embedded in iframes",
      url: url,
      details: {
        missingHeader: "X-Frame-Options",
        recommendation:
          "Add X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN",
      },
    };
  }

  const xFrameLower = xFrameOptions.toLowerCase();
  if (xFrameLower !== "deny" && xFrameLower !== "sameorigin") {
    return {
      type: "Clickjacking",
      severity: "MEDIUM",
      description: "Weak X-Frame-Options header value",
      url: url,
      details: {
        headerValue: xFrameOptions,
        recommendation: "Use X-Frame-Options: DENY for maximum security",
      },
    };
  }

  return null;
}

function detectOpenRedirect(url, requestBody) {
  const redirectParams = [
    "redirect",
    "url",
    "next",
    "target",
    "return",
    "returnTo",
    "goto",
    "link",
    "continue",
  ];
  const redirectDomains = [
    "evil.com",
    "attacker.com",
    "malicious.com",
    "phishing.com",
  ];

  // Check URL parameters
  try {
    const urlObj = new URL(url);
    for (const param of redirectParams) {
      const value = urlObj.searchParams.get(param);
      if (value) {
        // Check if it's an external URL
        try {
          const redirectUrl = new URL(value);
          if (redirectUrl.hostname !== urlObj.hostname) {
            return {
              type: "Open Redirect",
              severity: "HIGH",
              description: `Potential open redirect via ${param} parameter`,
              url: url,
              details: {
                parameter: param,
                redirectUrl: value,
                recommendation: "Validate and whitelist redirect URLs",
              },
            };
          }
        } catch (e) {
          // Not a valid URL, but could still be a relative redirect
          if (value.startsWith("//") || value.startsWith("http")) {
            return {
              type: "Open Redirect",
              severity: "MEDIUM",
              description: `Potential open redirect via ${param} parameter`,
              url: url,
              details: {
                parameter: param,
                redirectValue: value,
                recommendation: "Validate and whitelist redirect URLs",
              },
            };
          }
        }
      }
    }
  } catch (e) {
    // Invalid URL, skip
  }

  // Check request body for redirect parameters
  if (requestBody && requestBody.formData) {
    for (const [key, values] of Object.entries(requestBody.formData)) {
      if (redirectParams.includes(key.toLowerCase())) {
        for (const value of values) {
          const actualValue = value.original || value;
          try {
            const redirectUrl = new URL(actualValue);
            const urlObj = new URL(url);
            if (redirectUrl.hostname !== urlObj.hostname) {
              return {
                type: "Open Redirect",
                severity: "HIGH",
                description: `Potential open redirect via form parameter ${key}`,
                url: url,
                details: {
                  parameter: key,
                  redirectUrl: actualValue,
                  recommendation: "Validate and whitelist redirect URLs",
                },
              };
            }
          } catch (e) {
            // Not a valid URL
          }
        }
      }
    }
  }

  return null;
}

function detectMissingSecurityHeaders(url, headers) {
  const missingHeaders = [];
  const securityHeaders = {
    "x-content-type-options": "nosniff",
    "x-xss-protection": "1; mode=block",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'",
    "referrer-policy": "strict-origin-when-cross-origin",
  };

  for (const [header, recommendedValue] of Object.entries(securityHeaders)) {
    const headerValue = headers[header] || headers[header.toUpperCase()];
    if (!headerValue) {
      missingHeaders.push({
        header: header,
        recommendedValue: recommendedValue,
      });
    }
  }

  if (missingHeaders.length > 0) {
    return {
      type: "Missing Security Headers",
      severity: "MEDIUM",
      description: `Missing ${missingHeaders.length} security header(s)`,
      url: url,
      details: {
        missingHeaders: missingHeaders,
        recommendation: "Implement recommended security headers",
      },
    };
  }

  return null;
}

function detectSensitiveDataExposure(url, requestBody) {
  const sensitivePatterns = [
    { pattern: /password/i, name: "Password" },
    { pattern: /api[_-]?key/i, name: "API Key" },
    { pattern: /token/i, name: "Token" },
    { pattern: /secret/i, name: "Secret" },
    { pattern: /private[_-]?key/i, name: "Private Key" },
    { pattern: /credit[_-]?card/i, name: "Credit Card" },
    { pattern: /ssn/i, name: "SSN" },
    { pattern: /social[_-]?security/i, name: "Social Security" },
  ];

  // Check URL parameters
  try {
    const urlObj = new URL(url);
    for (const [param, value] of urlObj.searchParams.entries()) {
      for (const { pattern, name } of sensitivePatterns) {
        if (pattern.test(param) && value.length > 0) {
          return {
            type: "Sensitive Data Exposure",
            severity: "HIGH",
            description: `${name} parameter found in URL`,
            url: url,
            details: {
              parameter: param,
              recommendation: "Never expose sensitive data in URLs",
            },
          };
        }
      }
    }
  } catch (e) {
    // Invalid URL, skip
  }

  // Check request body
  if (requestBody && requestBody.formData) {
    for (const [key, values] of Object.entries(requestBody.formData)) {
      for (const { pattern, name } of sensitivePatterns) {
        if (pattern.test(key)) {
          return {
            type: "Sensitive Data Exposure",
            severity: "MEDIUM",
            description: `${name} parameter found in form data`,
            url: url,
            details: {
              parameter: key,
              recommendation: "Ensure sensitive data is properly encrypted",
            },
          };
        }
      }
    }
  }

  return null;
}

function runVulnerabilityScan(url, method, requestBody, responseHeaders = {}) {
  const vulnerabilities = [];

  // Only scan for certain types of requests
  if (method === "GET" || method === "POST") {
    // Clickjacking detection
    const clickjackingVuln = detectClickjackingVulnerability(
      url,
      responseHeaders
    );
    if (clickjackingVuln) vulnerabilities.push(clickjackingVuln);

    // Open redirect detection
    const openRedirectVuln = detectOpenRedirect(url, requestBody);
    if (openRedirectVuln) vulnerabilities.push(openRedirectVuln);

    // Missing security headers
    const missingHeadersVuln = detectMissingSecurityHeaders(
      url,
      responseHeaders
    );
    if (missingHeadersVuln) vulnerabilities.push(missingHeadersVuln);

    // Sensitive data exposure
    const sensitiveDataVuln = detectSensitiveDataExposure(url, requestBody);
    if (sensitiveDataVuln) vulnerabilities.push(sensitiveDataVuln);
  }

  return vulnerabilities;
}

// Enhanced vulnerability scan function with cloud detection
function runEnhancedVulnerabilityScan(completeRequest) {
  try {
    // Run existing vulnerability scans
    const vulnerabilities = runVulnerabilityScan(
      completeRequest.url,
      completeRequest.method,
      completeRequest.requestBody,
      completeRequest.response?.headers
    );

    // Store vulnerabilities in the request object
    completeRequest.vulnerabilities = vulnerabilities;

    // Add vulnerabilities to detection list
    vulnerabilities.forEach((vuln) => {
      const existingVuln = detectedVulnerabilities.find(
        (v) => v.type === vuln.type && v.url === vuln.url
      );
      if (!existingVuln) {
        detectedVulnerabilities.push(vuln);
      }
    });

    // NEW: Perform cloud provider detection
    const cloudAnalysis = cloudDetector
      ? cloudDetector.analyzeRequest(
          completeRequest.url,
          completeRequest.headers,
          completeRequest.response?.headers
        )
      : { summary: { isCloudService: false }, cloudProviders: [] };

    // Store cloud detection result in request
    completeRequest.cloudDetection = cloudAnalysis;

    // Store cloud detection result
    if (cloudAnalysis.summary.isCloudService) {
      cloudDetections.push(cloudAnalysis);
      enhancedData.cloudDetections.push(cloudAnalysis);

      // Send cloud detection update to popup
      safeSendMessage({
        action: "updateCloudDetections",
        detections: cloudDetections,
        stats: cloudDetector
          ? cloudDetector.getStatistics(cloudDetections)
          : {
              totalRequests: 0,
              cloudRequests: 0,
              providers: {},
              cloudPercentage: 0,
            },
      });
    }

    // Update popup with vulnerabilities
    if (vulnerabilities.length > 0) {
      safeSendMessage({
        action: "updateVulnerabilities",
        vulnerabilities: detectedVulnerabilities,
      });
    }
  } catch (error) {
    console.error("Error in enhanced vulnerability scan:", error);
  }
}

// Request listener function (legacy webRequest API)
function requestListener(details) {
  if (!isCapturing || !FILTERED_TYPES.includes(details.type)) return;

  // Build base request object (optimized - removed redundant fields)
  const request = {
    method: details.method,
    url: details.url,
    requestBody: processRequestBody(details.requestBody),
    ts: Date.now(), // Optimized: epoch milliseconds instead of ISO string
    // Removed: time (replaced with ts)
    // Removed: type (default assumption: xmlhttprequest)
    // Removed: tabId (not needed for security testing)
    requestId: details.requestId, // Keep temporarily for matching with response
    // flags used for decision later in responseListener
    sensitiveCandidate: false,
    hasSensitiveRequestHeaders: false,
  };

  // Note: Static resource detection is now done in export filtering, not stored

  // Quick URL-based sensitivity check (keywords/opaque tokens)
  if (urlContainsSensitiveKeywordOrOpaqueToken(details.url)) {
    request.sensitiveCandidate = true;
  }

  // If headers were already captured (rare, depends on ordering), attach them (filtered)
  const maybeHeaders = requestHeadersMap.get(details.requestId);
  if (maybeHeaders) {
    request.requestHeaders = filterSecurityHeaders(maybeHeaders);
    if (headerListHasSensitive(maybeHeaders)) {
      request.hasSensitiveRequestHeaders = true;
      request.sensitiveCandidate = true;
    }
  }

  // Store the request now; final retention decision may occur in responseListener
  capturedRequests.push(request);
  currentSession.requests.push(request);

  // Run vulnerability scan (keep behavior as before)
  const vulnerabilities = runVulnerabilityScan(details.url, details.method, details.requestBody);
  vulnerabilities.forEach((vuln) => {
    const existingVuln = detectedVulnerabilities.find((v) => v.type === vuln.type && v.url === vuln.url);
    if (!existingVuln) detectedVulnerabilities.push(vuln);
  });

  // Update popup with new request count and vulnerabilities
  safeSendMessage({ action: "updateRequestCount", count: capturedRequests.length });
  safeSendMessage({ action: "updateVulnerabilities", vulnerabilities: detectedVulnerabilities });
}

// Capture request headers so we can decide about sensitive headers
function requestHeadersListener(details) {
  try {
    if (!isCapturing) return;
    // Filter headers to keep only security-relevant ones
    const filteredHeaders = filterSecurityHeaders(details.requestHeaders || []);
    requestHeadersMap.set(details.requestId, filteredHeaders);

    // If we've already recorded a request for this id, attach filtered headers
    const req = capturedRequests.find((r) => r.requestId === details.requestId);
    if (req) {
      req.requestHeaders = filteredHeaders;
      if (headerListHasSensitive(details.requestHeaders || [])) {
        req.hasSensitiveRequestHeaders = true;
        req.sensitiveCandidate = true;
      }
    }
  } catch (e) {
    console.error("requestHeadersListener error:", e);
  }
}

// Response listener function to capture headers for vulnerability detection
function responseListener(details) {
  if (!isCapturing) return;

  // Find the corresponding request
  const request = capturedRequests.find((req) => req.requestId === details.requestId);
  if (!request) return;

  // Attach response metadata (filter headers to security-relevant only)
  request.responseHeaders = filterSecurityHeaders(details.responseHeaders || []);
  request.statusCode = details.statusCode;
  
  // Clean up requestId after response is matched (no longer needed)
  delete request.requestId;

  // Extract content-type from response headers
  const ctHeader = (details.responseHeaders || []).find(
    (h) => (h.name || "").toLowerCase() === "content-type"
  );
  const contentType = ctHeader ? (ctHeader.value || "") : "";

  // Decide whether to ignore this request because it's a static file that should not be captured
  const shouldIgnore = shouldIgnoreStaticCapture(request, { status: details.statusCode, contentType });
  if (shouldIgnore) {
    // Remove from capturedRequests and currentSession.requests
    const idx = capturedRequests.indexOf(request);
    if (idx !== -1) capturedRequests.splice(idx, 1);
    const idx2 = currentSession.requests.indexOf(request);
    if (idx2 !== -1) currentSession.requests.splice(idx2, 1);

    // Update popup count
    safeSendMessage({ action: "updateRequestCount", count: capturedRequests.length });
    return;
  }

  // Run vulnerability scan with response headers
  const vulnerabilities = runVulnerabilityScan(details.url, request.method, request.requestBody, details.responseHeaders);

  // Store vulnerabilities in the request object
  request.vulnerabilities = vulnerabilities;

  // Add new vulnerabilities to the list
  vulnerabilities.forEach((vuln) => {
    const existingVuln = detectedVulnerabilities.find((v) => v.type === vuln.type && v.url === vuln.url);
    if (!existingVuln) {
      detectedVulnerabilities.push(vuln);
      // Update popup with new vulnerabilities
      safeSendMessage({ action: "updateVulnerabilities", vulnerabilities: detectedVulnerabilities });
    }
  });

  // CRITICAL: Perform cloud provider detection
  if (cloudDetector) {
    try {
      const cloudAnalysis = cloudDetector.analyzeRequest(
        request.url,
        request.requestHeaders || [],
        details.responseHeaders || []
      );
      
      // Store cloud detection in request
      request.cloudDetection = cloudAnalysis;
      
      // Store in cloud detections list if it's a cloud service
      if (cloudAnalysis && cloudAnalysis.summary && cloudAnalysis.summary.isCloudService) {
        cloudDetections.push(cloudAnalysis);
        enhancedData.cloudDetections.push(cloudAnalysis);
        
        // Send cloud detection update to popup
        safeSendMessage({
          action: "updateCloudDetections",
          detections: cloudDetections,
          stats: cloudDetector.getStatistics(cloudDetections)
        });
      }
    } catch (error) {
      console.error("Error in cloud detection:", error);
    }
  }

  // CRITICAL: Extract and store query parameters from URL
  try {
    const urlObj = new URL(request.url);
    if (urlObj.searchParams && urlObj.searchParams.toString()) {
      request.queryParams = Object.fromEntries(urlObj.searchParams.entries());
    }
  } catch (e) {
    // Invalid URL, skip query param extraction
  }

  // CRITICAL: Classify the request comprehensively
  try {
    const completeRequest = {
      url: request.url,
      method: request.method,
      headers: request.requestHeaders || [],
      requestBody: request.requestBody,
      response: {
        headers: request.responseHeaders || [],
        status: request.statusCode
      },
      vulnerabilities: request.vulnerabilities || [],
      cloudDetection: request.cloudDetection
    };
    
    const classification = classifyRequest(completeRequest);
    addToClassifications(classification);
    
    // Send classification update to popup
    safeSendMessage({ 
      action: "classificationUpdate", 
      statistics: getClassificationStatistics() 
    });
  } catch (error) {
    console.error("Error classifying request:", error);
  }
}

function startCapture() {
  // Ensure extension is ready before starting capture
  if (!isExtensionReady) {
    console.warn("Extension not ready yet, cannot start capture. Will retry after initialization.");
    // Wait for initialization
    setTimeout(() => {
      if (isExtensionReady) {
        startCapture();
      } else {
        console.error("Extension initialization failed, cannot start capture");
      }
    }, 500);
    return;
  }

  // First, remove any existing listeners to avoid duplicates
  try {
    chrome.webRequest.onBeforeRequest.removeListener(requestListener);
  } catch (e) {
    // Ignore if listener wasn't registered
  }
  try {
    chrome.webRequest.onBeforeSendHeaders.removeListener(requestHeadersListener);
  } catch (e) {
    // Ignore if listener wasn't registered
  }
  try {
    chrome.webRequest.onResponseStarted.removeListener(responseListener);
  } catch (e) {
    // Ignore if listener wasn't registered
  }

  // Small delay to ensure listeners are fully removed before adding new ones
  setTimeout(() => {
    setupCaptureListeners();
  }, 50);
}

// Separate function to set up capture listeners (called after cleanup)
function setupCaptureListeners() {
  isCapturing = true;
  capturedRequests = []; // Clear previous captures
  currentSession.requests = []; // Clear previous session requests
  detectedVulnerabilities = []; // Clear previous vulnerabilities
  cloudDetections = []; // Clear previous cloud detections
  enhancedData = {
    networkTraffic: [],
    webStorage: {},
    domVulnerabilities: [],
    securityHeaders: {},
    sensitiveData: [],
    cloudDetections: [], // Clear cloud detections
    
    // Reset classifications (index-based)
    classifications: {
      byCloudProvider: {},
      byVulnerabilityType: {},
      bySecurityLevel: { critical: [], high: [], medium: [], low: [], info: [] },
      byEndpointType: { api: [], authentication: [], payment: [], user: [], static: [], other: [] },
      byDataSensitivity: { highlyConfidential: [], confidential: [], internal: [], public: [] },
      byProtocol: { https: [], http: [], wss: [], ws: [], other: [] },
      byRequestType: { GET: [], POST: [], PUT: [], DELETE: [], PATCH: [], OPTIONS: [], HEAD: [], other: [] },
      byContentType: { json: [], html: [], xml: [], formData: [], binary: [], text: [], other: [] },
      uncategorized: []
    }
  };

  safeSendMessage({
    action: "captureStatusChanged",
    isCapturing: true,
    requestCount: capturedRequests.length,
  });

  // Generate new session ID
  currentSession.sessionId = Date.now().toString();

  // Get cookies for the current domain
  chrome.cookies.getAll({}, function (cookies) {
    currentSession.cookies = cookies.reduce((acc, cookie) => {
      acc[cookie.name] = cookie.value;
      return acc;
    }, {});
  });

  // IMPORTANT: Set up fallback listeners FIRST (before tab query) to ensure capture starts immediately
  // This handles cold start scenarios where tab query might fail or be delayed
  const fallbackUrls = ["http://*/*", "https://*/*"];
  try {
    chrome.webRequest.onBeforeRequest.addListener(
      requestListener,
      { urls: fallbackUrls },
      ["requestBody"]
    );
    chrome.webRequest.onBeforeSendHeaders.addListener(
      requestHeadersListener,
      { urls: fallbackUrls },
      ["requestHeaders"]
    );
    chrome.webRequest.onResponseStarted.addListener(
      responseListener,
      { urls: fallbackUrls },
      ["responseHeaders"]
    );
    console.log("Capture listeners set up with fallback URL pattern (http/https)");
  } catch (error) {
    console.error("Error setting up fallback listeners:", error);
  }

  // Get current tab URL as target - consolidated single query
  chrome.tabs.query({ active: true, currentWindow: true }, async function (tabs) {
    if (!tabs || !tabs[0] || !tabs[0].url) {
      console.warn("No active tab found during capture start. Using fallback listeners.");
      // Listeners already set up above, just save state
      try {
        chrome.storage.local.set({
          isCapturing: true,
          currentSession: currentSession,
        });
      } catch (error) {
        console.error("Error saving capture state to storage:", error);
      }
      return;
    }

    const tab = tabs[0];
    currentSession.targetUrl = tab.url;

    try {
      // Extract domain for targeted capture
      try {
        const targetDomain = new URL(tab.url).hostname;
        const targetUrls = [
          `*://${targetDomain}/*`,
          `*://*.${targetDomain}/*`, // Include subdomains
        ];

        // Remove fallback listeners and set up targeted listeners
        // This provides better filtering while maintaining capture capability
        try {
          chrome.webRequest.onBeforeRequest.removeListener(requestListener);
          chrome.webRequest.onBeforeSendHeaders.removeListener(requestHeadersListener);
          chrome.webRequest.onResponseStarted.removeListener(responseListener);
        } catch (e) {
          // Ignore if listeners weren't registered
        }

        // Small delay to ensure listeners are fully removed
        setTimeout(() => {
          // Setup webRequest listeners with target URLs
          chrome.webRequest.onBeforeRequest.addListener(
            requestListener,
            { urls: targetUrls },
            ["requestBody"]
          );

          // Capture request headers so we can detect sensitive headers like Authorization
          chrome.webRequest.onBeforeSendHeaders.addListener(
            requestHeadersListener,
            { urls: targetUrls },
            ["requestHeaders"]
          );

          chrome.webRequest.onResponseStarted.addListener(
            responseListener,
            { urls: targetUrls },
            ["responseHeaders"]
          );
          console.log("Capture listeners updated to target domain:", targetDomain);
        }, 50);
      } catch (urlError) {
        console.error("Error parsing tab URL, using fallback listeners:", urlError);
        // Fallback listeners already set up, continue with those
      }

      // First, detach any existing debugger to avoid conflicts
      await detachDebugger(tab.id);
      
      // Small delay to ensure clean state
      setTimeout(() => {
        // Attach debugger for enhanced network capture
        attachDebugger(tab.id);
      }, 100);

      // Check if URL allows content script injection
      if (
        tab.url &&
        !tab.url.startsWith("chrome://") &&
        !tab.url.startsWith("chrome-extension://") &&
        !tab.url.startsWith("moz-extension://") &&
        !tab.url.startsWith("edge://") &&
        !tab.url.startsWith("about:")
      ) {
        // Collect web storage
        collectWebStorage(tab.id);

        // Analyze DOM security
        analyzeDOMSecurity(tab.id);
      } else {
        console.log("Skipping data collection for restricted URL:", tab.url);
        // Set empty data for restricted URLs
        enhancedData.webStorage = {
          localStorage: {},
          sessionStorage: {},
          cookies: {},
          error: "Restricted URL - cannot inject content script",
        };
        currentSession.webStorage = enhancedData.webStorage;

        enhancedData.domVulnerabilities = [];
        currentSession.domAnalysis = {
          vulnerabilities: [],
          analysisResults: { forms: [], xssSinks: [], insecureElements: [] },
          summary: {
            totalVulnerabilities: 0,
            highSeverity: 0,
            mediumSeverity: 0,
            lowSeverity: 0,
          },
          error: "Restricted URL - cannot inject content script",
        };
      }
    } catch (error) {
      console.error("Error setting up capture for tab:", error);
      // Fallback to http/https URLs if domain extraction fails
      // Use patterns that match manifest permissions
      try {
        chrome.webRequest.onBeforeRequest.addListener(
          requestListener,
          { urls: ["http://*/*", "https://*/*"] },
          ["requestBody"]
        );
        chrome.webRequest.onBeforeSendHeaders.addListener(
          requestHeadersListener,
          { urls: ["http://*/*", "https://*/*"] },
          ["requestHeaders"]
        );
        chrome.webRequest.onResponseStarted.addListener(
          responseListener,
          { urls: ["http://*/*", "https://*/*"] },
          ["responseHeaders"]
        );
        console.log("Capture started with fallback URL pattern (http/https) due to error");
      } catch (fallbackError) {
        console.error("Error setting up fallback listeners:", fallbackError);
      }
    }

    // Save state to storage
    try {
      chrome.storage.local.set({
        isCapturing: true,
        currentSession: currentSession,
      });
    } catch (error) {
      console.error("Error saving capture state to storage:", error);
    }
  });
}

function stopCapture() {
  isCapturing = false;
  chrome.webRequest.onBeforeRequest.removeListener(requestListener);
  try {
    chrome.webRequest.onBeforeSendHeaders.removeListener(requestHeadersListener);
  } catch (e) {
    // ignore if it wasn't registered
  }
  chrome.webRequest.onResponseStarted.removeListener(responseListener);

  // Detach debugger
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    if (tabs[0] && currentSession.debuggerAttached) {
      detachDebugger(tabs[0].id);
    }
  });

  // CRITICAL: Save state to storage with error handling - ensure all important data is preserved
  try {
    chrome.storage.local.set({
      isCapturing: false,
      capturedRequests: capturedRequests, // CRITICAL: All captured requests with full data
      currentSession: {
        ...currentSession,
        // Ensure all session data is preserved
        cookies: currentSession.cookies,
        webStorage: currentSession.webStorage,
        domAnalysis: currentSession.domAnalysis,
        targetUrl: currentSession.targetUrl,
        sessionId: currentSession.sessionId
      },
      detectedVulnerabilities: detectedVulnerabilities, // CRITICAL: All detected vulnerabilities
      cloudDetections: cloudDetections, // CRITICAL: Cloud provider detections
      enhancedData: {
        ...enhancedData,
        // Ensure all enhanced data is preserved
        classifications: enhancedData.classifications,
        cloudDetections: enhancedData.cloudDetections,
        webStorage: enhancedData.webStorage,
        domVulnerabilities: enhancedData.domVulnerabilities
      },
    });
    console.log("All capture data saved to storage successfully");
  } catch (error) {
    console.error("Error saving to storage:", error);
    // Try to save critical data separately if full save fails
    try {
      chrome.storage.local.set({
        capturedRequests: capturedRequests,
        detectedVulnerabilities: detectedVulnerabilities,
        currentSession: currentSession
      });
      console.log("Critical data saved to storage (partial save)");
    } catch (fallbackError) {
      console.error("Critical save also failed:", fallbackError);
    }
  }

  safeSendMessage({
    action: "captureStatusChanged",
    isCapturing: false,
    requestCount: capturedRequests.length,
  });
}

function downloadJson(filename) {
  if (capturedRequests.length === 0) {
    safeSendMessage({
      action: "downloadError",
      error: "No requests captured",
    });
    return;
  }

  try {
    // Create a comprehensive data structure with all collected information
    const data = {
      metadata: {
        timestamp: new Date().toISOString(),
        requestCount: capturedRequests.length,
        vulnerabilityCount: detectedVulnerabilities.length,
        cloudDetectionCount: cloudDetections.length,
        captureDuration: Date.now() - parseInt(currentSession.sessionId),
        enhancedCapture: true,
        dataStorage: "Single source of truth - capturedRequests array"
      },
      sessionId: currentSession.sessionId,
      targetUrl: currentSession.targetUrl,
      cookies: currentSession.cookies,
      vulnerabilities: detectedVulnerabilities,
      cloudDetections: cloudDetections,
      cloudStats: cloudDetector.getStatistics(cloudDetections),
      requests: capturedRequests
        .filter(req => !isStaticResource(req)) // Filter out static resources (CSS, images, fonts)
        .map((req) => ({
          // CRITICAL: All security-relevant data preserved
          method: req.method, // CRITICAL: HTTP method for attack vector selection
          url: req.url, // CRITICAL: Endpoint URL for testing
          ts: req.ts || (req.time ? new Date(req.time).getTime() : Date.now()), // Timestamp (optimized format)
          statusCode: req.statusCode, // CRITICAL: Response status for behavior analysis
          responseHeaders: req.responseHeaders, // CRITICAL: Security response headers (CSP, HSTS, etc.)
          requestBody: req.requestBody, // CRITICAL: Request body for injection testing (POST/PUT/PATCH)
          requestHeaders: req.requestHeaders, // CRITICAL: Auth headers, CSRF tokens, API keys
          queryParams: req.queryParams, // CRITICAL: Query parameters for injection testing
          vulnerabilities: req.vulnerabilities, // CRITICAL: Detected vulnerabilities per request
          cloudDetection: req.cloudDetection, // CRITICAL: Cloud provider detection
          classification: req.classification // Classification data for prioritization
        })),
      enhancedData: enhancedData,
      webStorage: currentSession.webStorage,
      domAnalysis: currentSession.domAnalysis,
      
      // Add comprehensive classifications (index-based)
      classifications: enhancedData.classifications,
      classificationStatistics: getClassificationStatistics(),
    };

    // Create JSON version
    const jsonString = JSON.stringify(data, null, 2);

    // Download JSON file
    const jsonDataUrl =
      "data:application/json;charset=utf-8," + encodeURIComponent(jsonString);
    chrome.downloads.download(
      {
        url: jsonDataUrl,
        filename: `${filename}.json`,
        saveAs: true,
      },
      (downloadId) => {
        if (chrome.runtime.lastError) {
          console.error("JSON download error:", chrome.runtime.lastError);
          safeSendMessage({
            action: "downloadError",
            error: chrome.runtime.lastError.message,
          });
        } else {
          console.log("JSON download started:", downloadId);
          safeSendMessage({
            action: "downloadJsonComplete",
            downloadId: downloadId,
          });
        }
      }
    );
  } catch (error) {
    console.error("Error preparing JSON download:", error);
    safeSendMessage({
      action: "downloadError",
      error: error.message,
    });
  }
}

function downloadTxt(filename) {
  if (capturedRequests.length === 0) {
    safeSendMessage({
      action: "downloadError",
      error: "No requests captured",
    });
    return;
  }

  try {
    // Create comprehensive human-readable TXT version
    const classificationStats = getClassificationStatistics();
    
    let txtContent = `Enhanced Browser Request Capture Report
Generated: ${new Date().toISOString()}
Session ID: ${currentSession.sessionId}
Target URL: ${currentSession.targetUrl}
Total Requests: ${capturedRequests.length}
Vulnerabilities Found: ${detectedVulnerabilities.length}
Cloud Services Detected: ${cloudDetections.length}
Capture Duration: ${Date.now() - parseInt(currentSession.sessionId)}ms
Enhanced Capture: Enabled
Data Storage: Single source of truth (capturedRequests array)

=== CLASSIFICATION SUMMARY ===
`;
    
    // Cloud Providers
    txtContent += `\nCloud Providers Detected:\n`;
    if (classificationStats.cloudProviders.length > 0) {
      classificationStats.cloudProviders.forEach(cp => {
        txtContent += `  - ${cp.provider}: ${cp.count} requests\n`;
      });
    } else {
      txtContent += `  No cloud providers detected\n`;
    }
    
    // Security Levels
    txtContent += `\nSecurity Levels:\n`;
    classificationStats.securityLevels.forEach(sl => {
      if (sl.count > 0) {
        txtContent += `  - ${sl.level.toUpperCase()}: ${sl.count} requests\n`;
      }
    });
    
    // Endpoint Types
    txtContent += `\nEndpoint Types:\n`;
    classificationStats.endpointTypes.forEach(et => {
      if (et.count > 0) {
        txtContent += `  - ${et.type}: ${et.count} requests\n`;
      }
    });
    
    // Data Sensitivity
    txtContent += `\nData Sensitivity Levels:\n`;
    classificationStats.dataSensitivity.forEach(ds => {
      if (ds.count > 0) {
        txtContent += `  - ${ds.level}: ${ds.count} requests\n`;
      }
    });
    
    // Protocols
    txtContent += `\nProtocols:\n`;
    classificationStats.protocols.forEach(p => {
      if (p.count > 0) {
        txtContent += `  - ${p.protocol.toUpperCase()}: ${p.count} requests\n`;
      }
    });
    
    // Request Methods
    txtContent += `\nHTTP Methods:\n`;
    classificationStats.requestMethods.forEach(rm => {
      if (rm.count > 0) {
        txtContent += `  - ${rm.method}: ${rm.count} requests\n`;
      }
    });
    
    // Vulnerabilities by Type
    txtContent += `\nVulnerabilities by Type:\n`;
    if (classificationStats.vulnerabilities.length > 0) {
      classificationStats.vulnerabilities.forEach(v => {
        txtContent += `  - ${v.type}: ${v.count} instances\n`;
      });
    } else {
      txtContent += `  No vulnerabilities detected\n`;
    }
    
    // Uncategorized
    if (classificationStats.uncategorized.count > 0) {
      txtContent += `\nSpecial Categories:\n`;
      txtContent += `  - Uncategorized: ${classificationStats.uncategorized.count} requests\n`;
    }

    txtContent += `\n=== CLOUD SERVICES DETECTED ===
`;

    if (cloudDetections.length === 0) {
      txtContent += "No cloud services detected.\n\n";
    } else {
      const cloudStats = cloudDetector
        ? cloudDetector.getStatistics(cloudDetections)
        : {
            totalRequests: 0,
            cloudRequests: 0,
            providers: {},
            cloudPercentage: 0,
          };
      txtContent += `Total Cloud Requests: ${cloudStats.cloudRequests} (${cloudStats.cloudPercentage}% of all requests)
      
`;

      if (cloudStats.topProvider) {
        txtContent += `Top Cloud Provider: ${cloudStats.topProvider.name} (${
          cloudStats.topProvider.count
        } requests)
Services Used: ${cloudStats.topProvider.services.join(", ")}

`;
      }

      txtContent += "Detailed Cloud Detections:\n";
      cloudDetections.forEach((detection, index) => {
        txtContent += `[${index + 1}] ${
          detection.summary.primaryProvider?.providerName || "Unknown Provider"
        }
URL: ${detection.url}
Confidence: ${(detection.summary.confidence * 100).toFixed(1)}%
Services: ${detection.summary.services.join(", ") || "Unknown"}
Detection Methods: ${detection.cloudProviders
          .map((cp) => cp.detectionMethod)
          .join(", ")}

`;
      });
    }

    txtContent += `=== VULNERABILITIES DETECTED ===
`;

    if (detectedVulnerabilities.length === 0) {
      txtContent += "No vulnerabilities detected.\n\n";
    } else {
      detectedVulnerabilities.forEach((vuln, index) => {
        txtContent += `[${index + 1}] ${vuln.type} (${vuln.severity})
Description: ${vuln.description}
URL: ${vuln.url}
Details: ${JSON.stringify(vuln.details, null, 2)}
Recommendation: ${vuln.details.recommendation}

`;
      });
    }

    txtContent += `=== WEB STORAGE DATA ===
${JSON.stringify(currentSession.webStorage, null, 2)}

=== DOM SECURITY ANALYSIS ===
${JSON.stringify(currentSession.domAnalysis, null, 2)}

=== COOKIES ===
${Object.entries(currentSession.cookies)
  .map(([name, value]) => `${name}: ${value}`)
  .join("\n")}

=== ENHANCED NETWORK TRAFFIC ===
${JSON.stringify(enhancedData.networkTraffic, null, 2)}

=== REQUESTS ===
`;

    capturedRequests.forEach((req, index) => {
      txtContent += `\n[${index + 1}] ${req.method} ${req.url}
Time: ${req.ts ? new Date(req.ts).toISOString() : (req.time || 'N/A')}
Status Code: ${req.statusCode || "N/A"}

`;

      if (req.responseHeaders) {
        txtContent += `Response Headers:\n`;
        req.responseHeaders.forEach((header) => {
          txtContent += `  ${header.name}: ${header.value}\n`;
        });
        txtContent += `\n`;
      }

      if (req.requestBody) {
        txtContent += `Request Body:\n`;

        if (req.requestBody.raw) {
          req.requestBody.raw.forEach((r, rawIndex) => {
            txtContent += `Raw Data ${rawIndex + 1} (${r.size} bytes):\n`;
            txtContent += `Text: ${r.text}\n`;
            txtContent += `Hex: ${r.bytes
              .map((b) => b.toString(16).padStart(2, "0"))
              .join(" ")}\n\n`;
          });
        }

        if (req.requestBody.formData) {
          txtContent += `Form Data:\n`;
          for (const [key, values] of Object.entries(
            req.requestBody.formData
          )) {
            txtContent += `${key}:\n`;
            values.forEach((value) => {
              txtContent += `  Original: ${value.original}\n`;
              txtContent += `  Decoded: ${value.decoded}\n`;
              txtContent += `  Is Base64: ${value.isBase64}\n`;
            });
            txtContent += "\n";
          }
        }
      }

      txtContent += "─".repeat(80) + "\n";
    });

    // Download TXT file
    const txtDataUrl =
      "data:text/plain;charset=utf-8," + encodeURIComponent(txtContent);
    chrome.downloads.download(
      {
        url: txtDataUrl,
        filename: `${filename}.txt`,
        saveAs: true,
      },
      (downloadId) => {
        if (chrome.runtime.lastError) {
          console.error("TXT download error:", chrome.runtime.lastError);
          safeSendMessage({
            action: "downloadError",
            error: chrome.runtime.lastError.message,
          });
        } else {
          console.log("TXT download started:", downloadId);
          safeSendMessage({
            action: "downloadTxtComplete",
            downloadId: downloadId,
          });
        }
      }
    );
  } catch (error) {
    console.error("Error preparing TXT download:", error);
    safeSendMessage({
      action: "downloadError",
      error: error.message,
    });
  }
}

// New: Enhanced Multi-File Download System
// Generates multiple categorized files for AI agent analysis
function downloadCategorizedFiles(filename) {
  if (capturedRequests.length === 0) {
    safeSendMessage({
      action: "downloadError",
      error: "No requests captured",
    });
    return;
  }

  try {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const baseFilename = filename || `capture_${timestamp}`;
    
    // Extract and organize data
    const organizedData = organizeDataForExport();
    
    // Generate individual files
    const files = [
      {
        name: `${baseFilename}_cookies.json`,
        content: generateCookiesFile(organizedData.cookies),
        type: 'json'
      },
      {
        name: `${baseFilename}_subdomains.txt`,
        content: generateSubdomainsFile(organizedData.subdomains),
        type: 'text'
      },
      {
        name: `${baseFilename}_critical_apis.json`,
        content: generateCriticalAPIsFile(organizedData.criticalAPIs),
        type: 'json'
      },
      {
        name: `${baseFilename}_query_parameters.json`,
        content: generateQueryParametersFile(organizedData.queryParams),
        type: 'json'
      },
      {
        name: `${baseFilename}_authentication.json`,
        content: generateAuthenticationFile(organizedData.authentication),
        type: 'json'
      },
      {
        name: `${baseFilename}_vulnerabilities.json`,
        content: generateVulnerabilitiesFile(organizedData.vulnerabilities),
        type: 'json'
      },
      {
        name: `${baseFilename}_cloud_services.json`,
        content: generateCloudServicesFile(organizedData.cloudServices),
        type: 'json'
      },
      {
        name: `${baseFilename}_sensitive_data.json`,
        content: generateSensitiveDataFile(organizedData.sensitiveData),
        type: 'json'
      },
      {
        name: `${baseFilename}_endpoints_api.json`,
        content: generateEndpointsFile(organizedData.endpoints.api),
        type: 'json'
      },
      {
        name: `${baseFilename}_endpoints_payment.json`,
        content: generateEndpointsFile(organizedData.endpoints.payment),
        type: 'json'
      },
      {
        name: `${baseFilename}_endpoints_user.json`,
        content: generateEndpointsFile(organizedData.endpoints.user),
        type: 'json'
      },
      {
        name: `${baseFilename}_security_headers.json`,
        content: generateSecurityHeadersFile(organizedData.securityHeaders),
        type: 'json'
      },
      {
        name: `${baseFilename}_web_storage.json`,
        content: generateWebStorageFile(organizedData.webStorage),
        type: 'json'
      },
      {
        name: `${baseFilename}_post_requests.json`,
        content: generatePostRequestsFile(organizedData.postRequests),
        type: 'json'
      },
      {
        name: `${baseFilename}_others.txt`,
        content: generateOthersFile(organizedData.others),
        type: 'text'
      },
      {
        name: `${baseFilename}_summary.txt`,
        content: generateSummaryFile(organizedData),
        type: 'text'
      },
      {
        name: `${baseFilename}_complete_raw.json`,
        content: JSON.stringify({
          metadata: organizedData.metadata,
          requests: organizedData.cleanedRequests.map(req => cleanRequestForExport(req)),
          vulnerabilities: detectedVulnerabilities,
          cloudDetections: cloudDetections
        }, null, 2),
        type: 'json'
      }
    ];
    
  // Package all files into a single ZIP and download
  generateZipAndDownload(files, baseFilename);
    
  } catch (error) {
    console.error("Error preparing categorized downloads:", error);
    safeSendMessage({
      action: "downloadError",
      error: error.message,
    });
  }
}

// Build the same categorized files the download produces, as a { name: content } map.
function buildCategorizedFilesMap(baseFilename) {
  const organizedData = organizeDataForExport();
  const entries = [
    [`${baseFilename}_cookies.json`, generateCookiesFile(organizedData.cookies)],
    [`${baseFilename}_subdomains.txt`, generateSubdomainsFile(organizedData.subdomains)],
    [`${baseFilename}_critical_apis.json`, generateCriticalAPIsFile(organizedData.criticalAPIs)],
    [`${baseFilename}_query_parameters.json`, generateQueryParametersFile(organizedData.queryParams)],
    [`${baseFilename}_authentication.json`, generateAuthenticationFile(organizedData.authentication)],
    [`${baseFilename}_vulnerabilities.json`, generateVulnerabilitiesFile(organizedData.vulnerabilities)],
    [`${baseFilename}_cloud_services.json`, generateCloudServicesFile(organizedData.cloudServices)],
    [`${baseFilename}_sensitive_data.json`, generateSensitiveDataFile(organizedData.sensitiveData)],
    [`${baseFilename}_endpoints_api.json`, generateEndpointsFile(organizedData.endpoints.api)],
    [`${baseFilename}_endpoints_payment.json`, generateEndpointsFile(organizedData.endpoints.payment)],
    [`${baseFilename}_endpoints_user.json`, generateEndpointsFile(organizedData.endpoints.user)],
    [`${baseFilename}_security_headers.json`, generateSecurityHeadersFile(organizedData.securityHeaders)],
    [`${baseFilename}_web_storage.json`, generateWebStorageFile(organizedData.webStorage)],
    [`${baseFilename}_post_requests.json`, generatePostRequestsFile(organizedData.postRequests)],
    [`${baseFilename}_others.txt`, generateOthersFile(organizedData.others)],
    [`${baseFilename}_summary.txt`, generateSummaryFile(organizedData)],
    [
      `${baseFilename}_complete_raw.json`,
      JSON.stringify(
        {
          metadata: organizedData.metadata,
          requests: organizedData.cleanedRequests.map((req) => cleanRequestForExport(req)),
          vulnerabilities: detectedVulnerabilities,
          cloudDetections: cloudDetections,
        },
        null,
        2
      ),
    ],
  ];
  const files = {};
  for (const [name, content] of entries) files[name] = content;
  return files;
}

// Send the current capture to the local harness gateway and start a scan.
async function sendCaptureToHarness(settings) {
  if (capturedRequests.length === 0) throw new Error("No requests captured");
  const baseUrl = (settings.url || "").replace(/\/+$/, "");
  if (!baseUrl) throw new Error("Server URL is not set");
  if (!settings.token) throw new Error("Token is not set");

  const headers = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${settings.token}`,
  };

  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const files = buildCategorizedFilesMap(`capture_${timestamp}`);
  const site = currentSession && currentSession.url ? new URL(currentSession.url).hostname : undefined;

  // 1. Upload the capture.
  const upRes = await fetch(`${baseUrl}/api/captures`, {
    method: "POST",
    headers,
    body: JSON.stringify({ site, files }),
  });
  if (!upRes.ok) throw new Error(`Upload failed (${upRes.status}): ${await safeErr(upRes)}`);
  const { captureId } = await upRes.json();

  // 2. Create the scan.
  const scope = (settings.scope || "")
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
  const scanRes = await fetch(`${baseUrl}/api/scans`, {
    method: "POST",
    headers,
    body: JSON.stringify({ captureId, mode: settings.mode || "passive", scope }),
  });
  if (!scanRes.ok) throw new Error(`Scan failed (${scanRes.status}): ${await safeErr(scanRes)}`);
  const scan = await scanRes.json();
  return { captureId, scanId: scan.scanId, mode: settings.mode || "passive" };
}

async function safeErr(res) {
  try {
    const body = await res.json();
    return body.error || JSON.stringify(body);
  } catch {
    return res.statusText;
  }
}

// Clean and optimize request data for export
function cleanRequestForExport(req) {
  const cleaned = {
    method: req.method,
    url: req.url,
    timestamp: req.ts || (req.timestamp ? new Date(req.timestamp).toISOString() : (req.time ? new Date(req.time).toISOString() : new Date().toISOString())),
    statusCode: req.statusCode || req.response?.status,
    // Removed: type (default assumption: xmlhttprequest)
  };

  // Add request body only for POST/PUT/PATCH (and only decoded text, no bytes)
  if (['POST', 'PUT', 'PATCH'].includes(req.method?.toUpperCase())) {
    if (req.requestBody) {
      // Extract only text, ignore bytes array
      if (req.requestBody.raw && Array.isArray(req.requestBody.raw)) {
        cleaned.requestBody = req.requestBody.raw.map(r => r.text).join('');
      } else if (typeof req.requestBody === 'string') {
        cleaned.requestBody = req.requestBody;
      }
    } else if (req.postData) {
      cleaned.requestBody = req.postData;
    }
  }

  // Consolidate headers - single representation, filter noise
  const headers = {};
  const headerSource = req.requestHeaders || req.headers || {};
  
  if (Array.isArray(headerSource)) {
    headerSource.forEach(h => {
      const name = h.name.toLowerCase();
      // Skip noisy/infrastructure headers
      if (!name.startsWith('sec-ch-') && 
          !name.startsWith(':') &&
          name !== 'priority' &&
          name !== 'accept-encoding' &&
          name !== 'accept-language') {
        headers[h.name] = h.value;
      }
    });
  } else {
    Object.entries(headerSource).forEach(([key, value]) => {
      const name = key.toLowerCase();
      if (!name.startsWith('sec-ch-') && 
          !name.startsWith(':') &&
          name !== 'priority' &&
          name !== 'accept-encoding' &&
          name !== 'accept-language') {
        headers[key] = value;
      }
    });
  }
  
  if (Object.keys(headers).length > 0) {
    cleaned.requestHeaders = headers;
  }

  // Response headers - filter noise (CDN/infrastructure headers)
  const responseHeaders = {};
  const respHeaderSource = req.responseHeaders || req.response?.headers || {};
  
  if (Array.isArray(respHeaderSource)) {
    respHeaderSource.forEach(h => {
      const name = h.name.toLowerCase();
      // Keep only security-relevant headers
      if (name === 'content-type' ||
          name === 'set-cookie' ||
          name === 'authorization' ||
          name === 'www-authenticate' ||
          name === 'x-frame-options' ||
          name === 'content-security-policy' ||
          name === 'strict-transport-security' ||
          name === 'x-content-type-options' ||
          name === 'x-xss-protection' ||
          name === 'referrer-policy' ||
          name === 'access-control-allow-origin' ||
          name === 'access-control-allow-credentials') {
        responseHeaders[h.name] = h.value;
      }
    });
  } else {
    Object.entries(respHeaderSource).forEach(([key, value]) => {
      const name = key.toLowerCase();
      if (name === 'content-type' ||
          name === 'set-cookie' ||
          name === 'authorization' ||
          name === 'www-authenticate' ||
          name === 'x-frame-options' ||
          name === 'content-security-policy' ||
          name === 'strict-transport-security' ||
          name === 'x-content-type-options' ||
          name === 'x-xss-protection' ||
          name === 'referrer-policy' ||
          name === 'access-control-allow-origin' ||
          name === 'access-control-allow-credentials') {
        responseHeaders[key] = value;
      }
    });
  }
  
  if (Object.keys(responseHeaders).length > 0) {
    cleaned.responseHeaders = responseHeaders;
  }

  // Minimal cookie data (only essential fields)
  if (req.associatedCookies && Array.isArray(req.associatedCookies)) {
    cleaned.cookies = req.associatedCookies.map(ac => ({
      name: ac.cookie?.name,
      value: ac.cookie?.value,
      domain: ac.cookie?.domain,
      httpOnly: ac.cookie?.httpOnly,
      secure: ac.cookie?.secure
    }));
  }

  // Classification and security info
  if (req.classification) {
    cleaned.classification = {
      endpointType: req.classification.endpointType,
      securityLevel: req.classification.securityLevel,
      dataSensitivity: req.classification.dataSensitivity
    };
  }

  // Vulnerabilities - reference only, details in separate file
  if (req.vulnerabilities && req.vulnerabilities.length > 0) {
    cleaned.vulnerabilityCount = req.vulnerabilities.length;
    cleaned.vulnerabilityTypes = [...new Set(req.vulnerabilities.map(v => v.type))];
  }

  // Cloud detection - minimal info
  if (req.cloudDetection?.summary?.isCloudService) {
    cleaned.cloudProvider = req.cloudDetection.summary.primaryProvider?.providerName;
  }

  // Duration only (no verbose timing)
  if (req.summary?.duration) {
    cleaned.duration = req.summary.duration;
  }

  return cleaned;
}

// Deduplicate requests (merge webRequest + CDP data) - optimized with body hash
function deduplicateRequests(requests) {
  const deduplicated = new Map();
  
  requests.forEach(req => {
    // Create hash based on method + URL + body (more accurate than timestamp)
    const bodyStr = req.requestBody ? JSON.stringify(req.requestBody) : '';
    const bodyHash = hashString(bodyStr);
    const key = `${req.method}||${req.url}||${bodyHash}`;
    
    if (!deduplicated.has(key)) {
      deduplicated.set(key, req);
    } else {
      // Merge: prefer CDP data (more complete) but keep webRequest data if missing
      const existing = deduplicated.get(key);
      deduplicated.set(key, {
        ...existing,
        ...req,
        // Merge headers
        requestHeaders: req.requestHeaders || existing.requestHeaders,
        responseHeaders: req.responseHeaders || existing.responseHeaders,
        // Merge classification
        classification: req.classification || existing.classification,
        vulnerabilities: req.vulnerabilities || existing.vulnerabilities,
        cloudDetection: req.cloudDetection || existing.cloudDetection
      });
    }
  });
  
  return Array.from(deduplicated.values());
}

function organizeDataForExport() {
  // First deduplicate requests
  const uniqueRequests = deduplicateRequests(capturedRequests);
  
  const data = {
    metadata: {
      sessionId: currentSession.sessionId,
      targetUrl: currentSession.targetUrl,
      timestamp: new Date().toISOString(),
      totalRequests: uniqueRequests.length,
      captureDuration: Date.now() - parseInt(currentSession.sessionId),
    },
    cookies: [],
    subdomains: new Set(),
    criticalAPIs: [],
    queryParams: {},
    authentication: [],
    vulnerabilities: detectedVulnerabilities,
    cloudServices: cloudDetections,
    sensitiveData: [],
    endpoints: {
      api: [],
      payment: [],
      user: [],
      static: [],
      other: []
    },
    securityHeaders: {},
    webStorage: currentSession.webStorage,
    postRequests: [],
    others: []
  };
  
  // Process each request (filter out static resources)
  uniqueRequests
    .filter(req => !isStaticResource(req)) // Filter static resources from export
    .forEach((req, index) => {
    try {
      const urlObj = new URL(req.url);
      
      // Extract subdomain
      if (urlObj.hostname) {
        data.subdomains.add(urlObj.hostname);
      }
      
      // Extract query parameters
      if (urlObj.search) {
        urlObj.searchParams.forEach((value, key) => {
          if (!data.queryParams[req.url]) {
            data.queryParams[req.url] = {};
          }
          data.queryParams[req.url][key] = value;
        });
      }
      
      // Classify request
      const classification = req.classification || {};
      
      // Critical APIs (high security level or authentication endpoints)
      if (classification.securityLevel === 'critical' || 
          classification.securityLevel === 'high' ||
          classification.endpointType === 'authentication' ||
          classification.endpointType === 'payment') {
        data.criticalAPIs.push({
          url: req.url,
          method: req.method,
          type: classification.endpointType,
          securityLevel: classification.securityLevel,
          timestamp: req.ts || (req.time ? new Date(req.time).toISOString() : new Date().toISOString()),
          statusCode: req.statusCode,
          hasAuth: req.responseHeaders?.some(h => 
            h.name.toLowerCase().includes('authorization') || 
            h.name.toLowerCase().includes('auth')
          )
        });
      }
      
      // Authentication related
      if (classification.endpointType === 'authentication' ||
          req.url.match(/login|signin|auth|token|oauth|sso/i) ||
          req.responseHeaders?.some(h => h.name.toLowerCase().includes('authorization'))) {
        data.authentication.push({
          url: req.url,
          method: req.method,
          timestamp: req.ts || (req.time ? new Date(req.time).toISOString() : new Date().toISOString()),
          statusCode: req.statusCode,
          headers: req.responseHeaders,
          hasCredentials: !!req.requestBody
        });
      }
      
      // Sensitive data detection
      if (classification.dataSensitivity?.level === 'highlyConfidential' ||
          classification.dataSensitivity?.level === 'confidential') {
        data.sensitiveData.push({
          url: req.url,
          method: req.method,
          sensitivityLevel: classification.dataSensitivity.level,
          reasons: classification.dataSensitivity.reasons,
          timestamp: req.ts || (req.time ? new Date(req.time).toISOString() : new Date().toISOString()),
          requestBody: req.requestBody
        });
      }
      
      // Categorize by endpoint type
      const endpointType = classification.endpointType || 'other';
      if (data.endpoints[endpointType]) {
        data.endpoints[endpointType].push({
          url: req.url,
          method: req.method,
          timestamp: req.ts || (req.time ? new Date(req.time).toISOString() : new Date().toISOString()),
          statusCode: req.statusCode
        });
      } else {
        data.endpoints.other.push({
          url: req.url,
          method: req.method,
          timestamp: req.ts || (req.time ? new Date(req.time).toISOString() : new Date().toISOString()),
          statusCode: req.statusCode
        });
      }
      
      // Security headers analysis
      if (req.responseHeaders) {
        const securityHeaderNames = [
          'strict-transport-security',
          'content-security-policy',
          'x-frame-options',
          'x-content-type-options',
          'x-xss-protection',
          'referrer-policy',
          'permissions-policy'
        ];
        
        req.responseHeaders.forEach(header => {
          const headerName = header.name.toLowerCase();
          if (securityHeaderNames.includes(headerName)) {
            if (!data.securityHeaders[req.url]) {
              data.securityHeaders[req.url] = {};
            }
            data.securityHeaders[req.url][header.name] = header.value;
          }
        });
      }
      
      // POST requests with body
      if (req.method === 'POST' && req.requestBody) {
        data.postRequests.push({
          url: req.url,
          timestamp: req.ts || (req.time ? new Date(req.time).toISOString() : new Date().toISOString()),
          statusCode: req.statusCode,
          requestBody: req.requestBody,
          contentType: req.responseHeaders?.find(h => 
            h.name.toLowerCase() === 'content-type'
          )?.value
        });
      }
      
      // Others (uncategorized or low priority)
      if (classification.endpointType === 'other' && 
          classification.endpointType !== 'static' &&
          !classification.cloudProvider) {
        data.others.push({
          url: req.url,
          method: req.method,
          timestamp: req.ts || (req.time ? new Date(req.time).toISOString() : new Date().toISOString()),
          note: 'Uncategorized request'
        });
      }
      
    } catch (error) {
      console.error('Error processing request:', error);
      data.others.push({
        url: req.url,
        method: req.method,
        error: error.message
      });
    }
  });
  
  // Process cookies
  Object.entries(currentSession.cookies).forEach(([name, value]) => {
    data.cookies.push({
      name,
      value,
      domain: currentSession.targetUrl ? new URL(currentSession.targetUrl).hostname : 'unknown',
      session: true  // Since we're capturing during session
    });
  });
  
  // Convert Set to Array
  data.subdomains = Array.from(data.subdomains);
  
  // Store cleaned deduplicated requests for complete_raw
  data.cleanedRequests = uniqueRequests;
  
  return data;
}

// File generation functions
function generateCookiesFile(cookies) {
  // Deduplicate cookies by name
  const uniqueCookies = new Map();
  
  cookies.forEach(c => {
    if (!uniqueCookies.has(c.name)) {
      uniqueCookies.set(c.name, c);
    }
  });
  
  // Categorize cookies by security level
  const categorized = {
    authentication: [],
    session: [],
    tracking: [],
    functional: []
  };
  
  uniqueCookies.forEach(c => {
    const nameLower = c.name.toLowerCase();
    const cookie = {
      name: c.name,
      domain: c.domain,
      httpOnly: c.httpOnly,
      secure: c.secure,
      sameSite: c.sameSite
    };
    
    // Only include value for non-sensitive cookies (for privacy)
    const isSensitive = nameLower.includes('session') || 
                       nameLower.includes('auth') || 
                       nameLower.includes('token') ||
                       nameLower.includes('jwt') ||
                       nameLower.includes('csrf');
    
    if (!isSensitive) {
      cookie.value = c.value;
    } else {
      cookie.valueRedacted = true;
      cookie.valueLength = c.value?.length || 0;
    }
    
    // Categorize
    if (nameLower.includes('auth') || nameLower.includes('token') || nameLower.includes('jwt')) {
      cookie.category = 'Authentication';
      categorized.authentication.push(cookie);
    } else if (nameLower.includes('session') || nameLower.includes('sess')) {
      cookie.category = 'Session Management';
      categorized.session.push(cookie);
    } else if (nameLower.includes('ga') || nameLower.includes('_utm') || nameLower.includes('analytics')) {
      cookie.category = 'Tracking/Analytics';
      categorized.tracking.push(cookie);
    } else {
      cookie.category = 'Functional';
      categorized.functional.push(cookie);
    }
  });
  
  return JSON.stringify({
    totalCookies: uniqueCookies.size,
    timestamp: new Date().toISOString(),
    categorizedCookies: categorized,
    securityAnalysis: {
      authCookies: categorized.authentication.length,
      sessionCookies: categorized.session.length,
      trackingCookies: categorized.tracking.length,
      functionalCookies: categorized.functional.length,
      recommendations: [
        'Verify all authentication cookies have HttpOnly flag',
        'Ensure Secure flag is set for cookies over HTTPS',
        'Check SameSite attribute to prevent CSRF',
        'Test for session fixation vulnerabilities',
        'Verify cookie expiration times are appropriate'
      ]
    }
  }, null, 2);
}

function generateSubdomainsFile(subdomains) {
  return `Subdomains Discovered
Generated: ${new Date().toISOString()}
Total Subdomains: ${subdomains.length}

${'='.repeat(80)}

${subdomains.map((sd, i) => `${i + 1}. ${sd}`).join('\n')}

${'='.repeat(80)}
Note: These are all unique domains/subdomains discovered during the capture session.
Use this for reconnaissance and mapping the attack surface.
`;
}

function generateCriticalAPIsFile(apis) {
  return JSON.stringify({
    totalCriticalAPIs: apis.length,
    timestamp: new Date().toISOString(),
    criticalAPIs: apis.map(api => ({
      url: api.url,
      method: api.method,
      type: api.type,
      securityLevel: api.securityLevel,
      timestamp: api.timestamp,
      statusCode: api.statusCode,
      priority: api.securityLevel === 'critical' ? 'URGENT' : 
                api.securityLevel === 'high' ? 'HIGH' : 'MEDIUM',
      recommendation: api.type === 'authentication' ? 
        'Review authentication mechanism, check for weak credentials, test for bypass' :
        api.type === 'payment' ?
        'Test for payment manipulation, check authorization, verify amount validation' :
        'Review for authorization issues, test for IDOR, check input validation'
    }))
  }, null, 2);
}

function generateQueryParametersFile(queryParams) {
  const paramAnalysis = {};
  
  Object.entries(queryParams).forEach(([url, params]) => {
    Object.keys(params).forEach(paramName => {
      if (!paramAnalysis[paramName]) {
        paramAnalysis[paramName] = {
          parameterName: paramName,
          foundInURLs: [],
          potentialVulnerabilities: []
        };
      }
      paramAnalysis[paramName].foundInURLs.push(url);
      
      // Check for common vulnerable parameters
      if (paramName.match(/id|uid|user|admin|role/i)) {
        paramAnalysis[paramName].potentialVulnerabilities.push('Potential IDOR vulnerability');
      }
      if (paramName.match(/redirect|url|next|return/i)) {
        paramAnalysis[paramName].potentialVulnerabilities.push('Potential Open Redirect');
      }
      if (paramName.match(/file|path|dir|folder/i)) {
        paramAnalysis[paramName].potentialVulnerabilities.push('Potential Path Traversal');
      }
      if (paramName.match(/search|query|q|keyword/i)) {
        paramAnalysis[paramName].potentialVulnerabilities.push('Potential XSS or SQL Injection');
      }
    });
  });
  
  return JSON.stringify({
    totalParameters: Object.keys(paramAnalysis).length,
    timestamp: new Date().toISOString(),
    parameters: paramAnalysis,
    recommendations: [
      'Test all parameters for injection attacks (SQL, XSS, Command Injection)',
      'Check for authorization bypass by manipulating ID parameters',
      'Test redirect parameters for open redirect vulnerabilities',
      'Verify file/path parameters for directory traversal',
      'Check for parameter pollution and HTTP parameter pollution'
    ]
  }, null, 2);
}

function generateAuthenticationFile(authRequests) {
  // Deduplicate by URL + Method
  const uniqueEndpoints = new Map();
  
  authRequests.forEach(req => {
    const key = `${req.method}_${req.url}`;
    
    // Keep the entry with more complete data (has statusCode and headers)
    if (!uniqueEndpoints.has(key) || (req.statusCode && req.headers)) {
      uniqueEndpoints.set(key, req);
    }
  });
  
  // Convert to array and clean up
  const cleanedEndpoints = Array.from(uniqueEndpoints.values()).map(req => {
    const cleaned = {
      url: req.url,
      method: req.method,
      statusCode: req.statusCode,
      hasCredentials: req.hasCredentials
    };
    
    // Extract only security-critical headers needed for testing/replay
    if (req.headers && Array.isArray(req.headers)) {
      const securityHeaders = {};
      
      req.headers.forEach(h => {
        const name = h.name.toLowerCase();
        // Keep only headers critical for auth testing and replay
        if (name === 'content-type' ||
            name === 'authorization' ||
            name === 'www-authenticate' ||
            name === 'set-cookie' ||
            name === 'access-control-allow-origin' ||
            name === 'access-control-allow-credentials' ||
            name === 'access-control-allow-methods' ||
            name === 'x-csrf-token' ||
            name === 'x-xsrf-token') {
          securityHeaders[h.name] = h.value;
        }
      });
      
      if (Object.keys(securityHeaders).length > 0) {
        cleaned.securityHeaders = securityHeaders;
      }
    }
    
    return cleaned;
  });
  
  return JSON.stringify({
    totalAuthenticationRequests: cleanedEndpoints.length,
    timestamp: new Date().toISOString(),
    authenticationEndpoints: cleanedEndpoints,
    testingGuidance: {
      purpose: 'These endpoints handle authentication. Test thoroughly for auth bypasses, credential issues, and session management flaws.',
      recommendedTools: ['Burp Suite', 'OWASP ZAP', 'Postman'],
      criticalHeaders: 'Pay attention to Authorization, Set-Cookie, and CSRF token headers'
    },
    securityChecklist: [
      '✓ Check for weak password policies',
      '✓ Test for username enumeration',
      '✓ Verify rate limiting on login attempts',
      '✓ Check for account lockout mechanisms',
      '✓ Test for credential stuffing vulnerabilities',
      '✓ Verify multi-factor authentication implementation',
      '✓ Check for insecure password reset mechanisms',
      '✓ Test for session fixation vulnerabilities',
      '✓ Verify secure token generation and storage',
      '✓ Check for OAuth/SSO misconfigurations'
    ]
  }, null, 2);
}

function generateVulnerabilitiesFile(vulnerabilities) {
  const grouped = {};
  vulnerabilities.forEach(vuln => {
    if (!grouped[vuln.type]) {
      grouped[vuln.type] = [];
    }
    grouped[vuln.type].push(vuln);
  });
  
  return JSON.stringify({
    totalVulnerabilities: vulnerabilities.length,
    timestamp: new Date().toISOString(),
    vulnerabilitiesByType: grouped,
    severitySummary: {
      critical: vulnerabilities.filter(v => v.severity === 'critical').length,
      high: vulnerabilities.filter(v => v.severity === 'high').length,
      medium: vulnerabilities.filter(v => v.severity === 'medium').length,
      low: vulnerabilities.filter(v => v.severity === 'low').length,
      info: vulnerabilities.filter(v => v.severity === 'info').length
    },
    allVulnerabilities: vulnerabilities
  }, null, 2);
}

function generateCloudServicesFile(cloudServices) {
  // Deduplicate by URL
  const uniqueDetections = new Map();
  
  cloudServices.forEach(detection => {
    const url = detection.url;
    if (!uniqueDetections.has(url)) {
      uniqueDetections.set(url, detection);
    }
  });
  
  // Build provider summary
  const providers = {};
  uniqueDetections.forEach(detection => {
    const provider = detection.summary?.primaryProvider?.providerName || 'Unknown';
    if (!providers[provider]) {
      providers[provider] = {
        count: 0,
        confidence: detection.summary?.confidence || 0,
        services: new Set(),
        endpoints: []
      };
    }
    providers[provider].count++;
    if (detection.summary?.services) {
      detection.summary.services.forEach(s => providers[provider].services.add(s));
    }
    // Store only essential endpoint info
    providers[provider].endpoints.push({
      url: detection.url,
      detectionMethod: detection.cloudProviders?.[0]?.detectionMethod || 'unknown'
    });
  });
  
  // Convert Sets to Arrays
  Object.keys(providers).forEach(key => {
    providers[key].services = Array.from(providers[key].services);
    // Limit to top 10 endpoints per provider to reduce size
    if (providers[key].endpoints.length > 10) {
      providers[key].endpoints = providers[key].endpoints.slice(0, 10);
      providers[key].endpointsNote = `Showing 10 of ${providers[key].count} total endpoints`;
    }
  });
  
  return JSON.stringify({
    totalCloudDetections: uniqueDetections.size,
    timestamp: new Date().toISOString(),
    providersSummary: providers,
    analysis: {
      purpose: 'Identifies cloud infrastructure used by the application',
      securityNote: 'Cloud services may expose additional attack surface through misconfigurations',
      commonIssues: [
        'Publicly accessible storage buckets',
        'Misconfigured CDN caching sensitive data',
        'Exposed cloud function endpoints',
        'Weak CORS policies on cloud APIs'
      ]
    }
  }, null, 2);
}

function generateSensitiveDataFile(sensitiveData) {
  return JSON.stringify({
    totalSensitiveEndpoints: sensitiveData.length,
    timestamp: new Date().toISOString(),
    sensitiveDataEndpoints: sensitiveData.map(item => ({
      url: item.url,
      method: item.method,
      sensitivityLevel: item.sensitivityLevel,
      reasons: item.reasons,
      timestamp: item.timestamp
    })),
    securityWarning: 'These endpoints handle sensitive data. Ensure proper encryption, authentication, and authorization.',
    recommendations: [
      'Verify all sensitive data is transmitted over HTTPS',
      'Check for proper authentication on all endpoints',
      'Ensure authorization checks prevent unauthorized access',
      'Verify data is encrypted at rest',
      'Check for data leakage in error messages',
      'Test for mass assignment vulnerabilities',
      'Verify proper input validation and sanitization'
    ]
  }, null, 2);
}

function generateEndpointsFile(endpoints) {
  // Deduplicate by URL and method
  const uniqueEndpoints = new Map();
  
  endpoints.forEach(e => {
    const key = `${e.method}_${e.url}`;
    if (!uniqueEndpoints.has(key)) {
      uniqueEndpoints.set(key, {
        url: e.url,
        method: e.method,
        statusCode: e.statusCode
      });
    }
  });
  
  const endpointArray = Array.from(uniqueEndpoints.values());
  
  // Extract clean base paths for better organization
  const pathAnalysis = {};
  endpointArray.forEach(e => {
    try {
      const url = new URL(e.url);
      const pathSegments = url.pathname.split('/').filter(s => s);
      const basePath = pathSegments.length > 0 ? `/${pathSegments[0]}` : '/';
      
      if (!pathAnalysis[basePath]) {
        pathAnalysis[basePath] = { count: 0, methods: new Set() };
      }
      pathAnalysis[basePath].count++;
      pathAnalysis[basePath].methods.add(e.method);
    } catch (err) {
      // Skip invalid URLs
    }
  });
  
  // Convert Sets to arrays for JSON serialization
  Object.keys(pathAnalysis).forEach(path => {
    pathAnalysis[path].methods = Array.from(pathAnalysis[path].methods);
  });
  
  return JSON.stringify({
    totalUniqueEndpoints: endpointArray.length,
    timestamp: new Date().toISOString(),
    endpoints: endpointArray,
    methodDistribution: {
      GET: endpointArray.filter(e => e.method === 'GET').length,
      POST: endpointArray.filter(e => e.method === 'POST').length,
      PUT: endpointArray.filter(e => e.method === 'PUT').length,
      DELETE: endpointArray.filter(e => e.method === 'DELETE').length,
      PATCH: endpointArray.filter(e => e.method === 'PATCH').length,
      OTHER: endpointArray.filter(e => !['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].includes(e.method)).length
    },
    pathAnalysis: pathAnalysis,
    testingGuidance: [
      'Test each unique endpoint with different HTTP methods',
      'Check for method-based access control (e.g., DELETE without auth)',
      'Verify authorization enforcement across all endpoints',
      'Test for IDOR vulnerabilities with different resource IDs',
      'Check for rate limiting and throttling controls'
    ]
  }, null, 2);
}

function generateSecurityHeadersFile(securityHeaders) {
  const analysis = {
    urlsWithSecurityHeaders: Object.keys(securityHeaders).length,
    urlsMissingHeaders: [],
    headerCoverage: {}
  };
  
  const requiredHeaders = [
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options'
  ];
  
  // Analyze coverage
  capturedRequests.forEach(req => {
    if (!securityHeaders[req.url]) {
      analysis.urlsMissingHeaders.push(req.url);
    }
  });
  
  return JSON.stringify({
    timestamp: new Date().toISOString(),
    ...analysis,
    detailedHeaders: securityHeaders,
    recommendations: [
      'Implement HSTS (Strict-Transport-Security) on all pages',
      'Add Content-Security-Policy to prevent XSS attacks',
      'Use X-Frame-Options to prevent clickjacking',
      'Set X-Content-Type-Options: nosniff',
      'Implement Referrer-Policy for privacy',
      'Use Permissions-Policy to control browser features'
    ]
  }, null, 2);
}

function generateWebStorageFile(webStorage) {
  return JSON.stringify({
    timestamp: new Date().toISOString(),
    webStorage: webStorage,
    securityNotes: {
      localStorage: 'Check for sensitive data stored in localStorage (accessible via XSS)',
      sessionStorage: 'Verify session data is cleared on logout',
      cookies: 'Check for HttpOnly and Secure flags on sensitive cookies'
    },
    recommendations: [
      'Never store sensitive data in localStorage/sessionStorage',
      'Use HttpOnly cookies for session tokens',
      'Implement proper session expiration',
      'Clear storage on logout',
      'Encrypt sensitive data before storing'
    ]
  }, null, 2);
}

function generatePostRequestsFile(postRequests) {
  return JSON.stringify({
    totalPOSTRequests: postRequests.length,
    timestamp: new Date().toISOString(),
    postRequests: postRequests.map(req => ({
      url: req.url,
      timestamp: req.ts || (req.timestamp ? new Date(req.timestamp).toISOString() : new Date().toISOString()),
      statusCode: req.statusCode,
      contentType: req.contentType,
      hasBody: !!req.requestBody,
      testingNotes: 'Test for: SQL Injection, XSS, CSRF, Mass Assignment, Business Logic flaws'
    })),
    recommendations: [
      'Test all POST endpoints for CSRF protection',
      'Verify input validation on all parameters',
      'Check for SQL injection in form fields',
      'Test for XSS in reflected parameters',
      'Verify authorization on state-changing operations',
      'Check for race conditions in critical operations',
      'Test file upload endpoints for malicious files'
    ]
  }, null, 2);
}

function generateOthersFile(others) {
  return `Uncategorized Requests
Generated: ${new Date().toISOString()}
Total: ${others.length}

${'='.repeat(80)}

These requests didn't fit into specific categories but may still be relevant:

${others.map((req, i) => `
[${i + 1}] ${req.method} ${req.url}
    Time: ${req.timestamp}
    Note: ${req.note || req.error || 'Review manually'}
`).join('\n')}

${'='.repeat(80)}
Recommendations:
- Review each request manually for potential security issues
- Check if these are part of the application's normal functionality
- Look for hidden APIs or debugging endpoints
- Verify if authentication is required
`;
}

function generateSummaryFile(data) {
  return `AI CYBER SHIELD - CAPTURE SUMMARY REPORT
${'='.repeat(80)}

Session Information:
  Session ID: ${data.metadata.sessionId}
  Target URL: ${data.metadata.targetUrl}
  Capture Time: ${data.metadata.timestamp}
  Duration: ${(data.metadata.captureDuration / 1000).toFixed(2)} seconds
  Total Requests: ${data.metadata.totalRequests}

${'='.repeat(80)}

DATA SUMMARY:

Cookies:
  Total: ${data.cookies.length}
  Files: ${data.metadata.sessionId}_cookies.json

Subdomains:
  Total: ${data.subdomains.length}
  Files: ${data.metadata.sessionId}_subdomains.txt

Critical APIs:
  Total: ${data.criticalAPIs.length}
  Files: ${data.metadata.sessionId}_critical_apis.json
  Priority: ${data.criticalAPIs.filter(a => a.securityLevel === 'critical').length} CRITICAL, ${data.criticalAPIs.filter(a => a.securityLevel === 'high').length} HIGH

Query Parameters:
  Total Unique: ${Object.keys(data.queryParams).length}
  Files: ${data.metadata.sessionId}_query_parameters.json

Authentication Endpoints:
  Total: ${data.authentication.length}
  Files: ${data.metadata.sessionId}_authentication.json

Vulnerabilities:
  Total: ${data.vulnerabilities.length}
  Files: ${data.metadata.sessionId}_vulnerabilities.json
  Critical: ${data.vulnerabilities.filter(v => v.severity === 'critical').length}
  High: ${data.vulnerabilities.filter(v => v.severity === 'high').length}
  Medium: ${data.vulnerabilities.filter(v => v.severity === 'medium').length}

Cloud Services:
  Total Detections: ${data.cloudServices.length}
  Files: ${data.metadata.sessionId}_cloud_services.json

Sensitive Data:
  Endpoints: ${data.sensitiveData.length}
  Files: ${data.metadata.sessionId}_sensitive_data.json

Endpoints by Type:
  API: ${data.endpoints.api.length}
  Payment: ${data.endpoints.payment.length}
  User: ${data.endpoints.user.length}
  Static: ${data.endpoints.static.length}
  Other: ${data.endpoints.other.length}

Security Headers:
  URLs with Headers: ${Object.keys(data.securityHeaders).length}
  Files: ${data.metadata.sessionId}_security_headers.json

POST Requests:
  Total: ${data.postRequests.length}
  Files: ${data.metadata.sessionId}_post_requests.json

Uncategorized:
  Total: ${data.others.length}
  Files: ${data.metadata.sessionId}_others.txt

${'='.repeat(80)}

AI AGENT INSTRUCTIONS:

1. START with the SUMMARY file (this file) to understand the scope
2. Review CRITICAL_APIS for high-priority targets
3. Check VULNERABILITIES for immediate security issues
4. Analyze AUTHENTICATION endpoints for auth bypass opportunities
5. Review QUERY_PARAMETERS for injection points
6. Check SENSITIVE_DATA for data exposure risks
7. Analyze POST_REQUESTS for state-changing operations
8. Review SECURITY_HEADERS for missing protections
9. Check COOKIES for session management issues
10. Review WEB_STORAGE for client-side data exposure
11. Analyze CLOUD_SERVICES for cloud misconfigurations
12. Check SUBDOMAINS for additional attack surface
13. Review OTHERS for hidden/debug endpoints
14. Use COMPLETE_RAW for full technical details

${'='.repeat(80)}

PRIORITY TESTING ORDER:
1. Authentication & Authorization
2. Critical APIs & Payment Endpoints
3. Input Validation (Query Params, POST data)
4. Session Management (Cookies, Tokens)
5. Security Headers & Configurations
6. Cloud Service Integrations
7. Data Exposure & Sensitive Information
8. Uncategorized Endpoints

${'='.repeat(80)}

Generated by AI Cyber Shield
All files are structured for both human analysis and AI agent processing.
`;
}

function downloadFilesSequentially(files, index) {
  if (index >= files.length) {
    safeSendMessage({
      action: "downloadComplete",
      filesDownloaded: files.length
    });
    return;
  }
  
  const file = files[index];
  const mimeType = file.type === 'json' ? 'application/json' : 'text/plain';
  const dataUrl = `data:${mimeType};charset=utf-8,` + encodeURIComponent(file.content);
  
  chrome.downloads.download(
    {
      url: dataUrl,
      filename: file.name,
      saveAs: false  // Auto-save to avoid too many prompts
    },
    (downloadId) => {
      if (chrome.runtime.lastError) {
        console.error(`Error downloading ${file.name}:`, chrome.runtime.lastError);
      } else {
        console.log(`Downloaded: ${file.name} (ID: ${downloadId})`);
      }
      
      // Download next file after a short delay
      setTimeout(() => {
        downloadFilesSequentially(files, index + 1);
      }, 300);  // 300ms delay between downloads
    }
  );
}

// ZIP creation (store method, no compression) and download
function generateZipAndDownload(files, zipName) {
  try {
    // Helper: CRC32
    function crc32(buf) {
      const table = (function() {
        let c; const table = new Uint32Array(256);
        for (let n = 0; n < 256; n++) {
          c = n;
          for (let k = 0; k < 8; k++) {
            c = ((c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1));
          }
          table[n] = c >>> 0;
        }
        return table;
      })();

      let crc = 0 ^ (-1);
      for (let i = 0; i < buf.length; i++) {
        crc = (crc >>> 8) ^ table[(crc ^ buf[i]) & 0xFF];
      }
      return (crc ^ (-1)) >>> 0;
    }

    function u32(n) {
      return [n & 0xFF, (n >>> 8) & 0xFF, (n >>> 16) & 0xFF, (n >>> 24) & 0xFF];
    }

    const encoder = new TextEncoder();
    const parts = [];
    const centralDirectory = [];
    let offset = 0;

    files.forEach((file) => {
      const filenameBytes = encoder.encode(file.name);
      const contentBytes = encoder.encode(file.content);
      const crc = crc32(contentBytes);
      const compressedSize = contentBytes.length;
      const uncompressedSize = contentBytes.length;

      // Local file header (no compression)
      const localHeader = [];
      // local file header signature
      localHeader.push(...u32(0x04034b50));
      // version needed to extract
      localHeader.push(20, 0);
      // general purpose bit flag
      localHeader.push(0, 0);
      // compression method (0 = store)
      localHeader.push(0, 0);
      // last mod file time & date (set to zero)
      localHeader.push(0, 0, 0, 0);
      // crc32
      localHeader.push(...u32(crc));
      // compressed size
      localHeader.push(...u32(compressedSize));
      // uncompressed size
      localHeader.push(...u32(uncompressedSize));
      // filename length
      localHeader.push(...[filenameBytes.length & 0xFF, (filenameBytes.length >>> 8) & 0xFF]);
      // extra field length
      localHeader.push(0, 0);

      parts.push(new Uint8Array(localHeader));
      parts.push(filenameBytes);
      parts.push(contentBytes);

      // central directory file header
      const centralHeader = [];
      // central file header signature
      centralHeader.push(...u32(0x02014b50));
      // version made by
      centralHeader.push(20, 0);
      // version needed to extract
      centralHeader.push(20, 0);
      // general purpose bit flag
      centralHeader.push(0, 0);
      // compression method
      centralHeader.push(0, 0);
      // file mod time & date
      centralHeader.push(0, 0, 0, 0);
      // crc
      centralHeader.push(...u32(crc));
      // compressed size
      centralHeader.push(...u32(compressedSize));
      // uncompressed size
      centralHeader.push(...u32(uncompressedSize));
      // filename length
      centralHeader.push(...[filenameBytes.length & 0xFF, (filenameBytes.length >>> 8) & 0xFF]);
      // extra field length
      centralHeader.push(0, 0);
      // file comment length
      centralHeader.push(0, 0);
      // disk number start
      centralHeader.push(0, 0);
      // internal file attrs
      centralHeader.push(0, 0);
      // external file attrs
      centralHeader.push(0, 0, 0, 0);
      // relative offset of local header
      centralHeader.push(...u32(offset));

      centralDirectory.push(new Uint8Array(centralHeader));
      centralDirectory.push(filenameBytes);

      // Update offset: local header size + filename + content
      offset += localHeader.length + filenameBytes.length + contentBytes.length;
    });

    // Concatenate central directory
    const centralStart = offset;
    let centralSize = 0;
    centralDirectory.forEach((part) => {
      centralSize += part.length;
    });

    // End of central directory record
    const endRecord = [];
    // end of central dir signature
    endRecord.push(...u32(0x06054b50));
    // number of this disk
    endRecord.push(0, 0);
    // number of the disk with the start of the central directory
    endRecord.push(0, 0);
    // total number of entries in the central directory on this disk
    const totalEntries = files.length;
    endRecord.push(...[totalEntries & 0xFF, (totalEntries >>> 8) & 0xFF]);
    // total number of entries
    endRecord.push(...[totalEntries & 0xFF, (totalEntries >>> 8) & 0xFF]);
    // size of the central directory
    endRecord.push(...u32(centralSize));
    // offset of start of central directory
    endRecord.push(...u32(centralStart));
    // comment length
    endRecord.push(0, 0);

    // Create final blob
    const allParts = parts.concat(centralDirectory);
    allParts.push(new Uint8Array(endRecord));

    // Compute total length
    let totalLength = 0;
    allParts.forEach(p => totalLength += p.length);

    const buffer = new Uint8Array(totalLength);
    let pointer = 0;
    allParts.forEach(p => {
      buffer.set(p, pointer);
      pointer += p.length;
    });

    // Convert to base64 data URL
    function base64ArrayBuffer(arrayBuffer) {
      let base64 = '';
      const encodings = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

      const bytes = new Uint8Array(arrayBuffer);
      const byteLength = bytes.byteLength;
      let byteRemainder = byteLength % 3;
      let mainLength = byteLength - byteRemainder;

      let a, b, c, d;
      let chunk;

      for (let i = 0; i < mainLength; i += 3) {
        chunk = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
        a = (chunk >> 18) & 63;
        b = (chunk >> 12) & 63;
        c = (chunk >> 6) & 63;
        d = chunk & 63;
        base64 += encodings[a] + encodings[b] + encodings[c] + encodings[d];
      }

      if (byteRemainder === 1) {
        chunk = bytes[mainLength];
        a = (chunk >> 2) & 63;
        b = (chunk << 4) & 63;
        base64 += encodings[a] + encodings[b] + '==';
      } else if (byteRemainder === 2) {
        chunk = (bytes[mainLength] << 8) | bytes[mainLength + 1];
        a = (chunk >> 10) & 63;
        b = (chunk >> 4) & 63;
        c = (chunk << 2) & 63;
        base64 += encodings[a] + encodings[b] + encodings[c] + '=';
      }

      return base64;
    }

    const base64 = base64ArrayBuffer(buffer.buffer);
    const dataUrl = 'data:application/zip;base64,' + base64;

    chrome.downloads.download({
      url: dataUrl,
      filename: zipName + '.zip',
      saveAs: true
    }, (downloadId) => {
      if (chrome.runtime.lastError) {
        console.error('Zip download error:', chrome.runtime.lastError);
        safeSendMessage({ action: 'downloadError', error: chrome.runtime.lastError.message });
      } else {
        console.log('ZIP download started:', downloadId);
        safeSendMessage({ action: 'downloadComplete', filesDownloaded: files.length, zipDownloadId: downloadId });
      }
    });

  } catch (err) {
    console.error('Error creating ZIP:', err);
    safeSendMessage({ action: 'downloadError', error: err.message });
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Check if extension is ready before processing messages
  if (!isExtensionReady) {
    if (message.action === "startCapture") {
      console.log("Extension not ready yet, queuing start capture request");
      pendingCaptureStart = true;
      sendResponse({
        status: "initializing",
        message: "Extension is still initializing, capture will start automatically",
      });
      return true;
    }

    if (message.action === "stopCapture") {
      console.log("Stop requested while initializing - clearing pending start");
      pendingCaptureStart = false;
      sendResponse({ status: "stopped" });
      return true;
    }

    console.log("Extension not ready yet, queuing message:", message.action);
    sendResponse({
      status: "not_ready",
      error: "Extension is still initializing, please try again in a moment",
    });
    return true;
  }

  if (message.action === "startCapture") {
    pendingCaptureStart = false;
    startCapture();
    sendResponse({ status: "started" });
  }

  if (message.action === "stopCapture") {
    pendingCaptureStart = false;
    stopCapture();
    sendResponse({ status: "stopped" });
  }

  if (message.action === "getRequests") {
    sendResponse({ requests: capturedRequests });
  }

  if (message.action === "getCaptureStatus") {
    sendResponse({
      isCapturing,
      requestCount: capturedRequests.length,
      sessionId: currentSession.sessionId,
      targetUrl: currentSession.targetUrl,
      cookies: currentSession.cookies,
      vulnerabilities: detectedVulnerabilities,
      cloudDetections: cloudDetections,
      cloudStats: cloudDetector
        ? cloudDetector.getStatistics(cloudDetections)
        : {
            totalRequests: 0,
            cloudRequests: 0,
            providers: {},
            cloudPercentage: 0,
          },
      // Add classification statistics
      classifications: getClassificationStatistics(),
    });
  }
  
  // New: Get classification statistics
  if (message.action === "getClassifications") {
    sendResponse({
      classifications: enhancedData.classifications,
      statistics: getClassificationStatistics(),
    });
  }
  
  // New: Get ALL requests (from single source of truth)
  if (message.action === "getAllClassifications") {
    sendResponse({
      allClassifications: capturedRequests,
      count: capturedRequests.length,
      message: "Complete list - single source of truth"
    });
  }
  
  // New: Get requests by classification
  if (message.action === "getRequestsByClassification") {
    const { type, value } = message;
    let indices = [];
    
    switch(type) {
      case 'cloudProvider':
        indices = enhancedData.classifications.byCloudProvider[value] || [];
        break;
      case 'vulnerability':
        indices = enhancedData.classifications.byVulnerabilityType[value] || [];
        break;
      case 'securityLevel':
        indices = enhancedData.classifications.bySecurityLevel[value] || [];
        break;
      case 'endpointType':
        indices = enhancedData.classifications.byEndpointType[value] || [];
        break;
      case 'dataSensitivity':
        indices = enhancedData.classifications.byDataSensitivity[value] || [];
        break;
      case 'protocol':
        indices = enhancedData.classifications.byProtocol[value] || [];
        break;
      case 'requestMethod':
        indices = enhancedData.classifications.byRequestType[value] || [];
        break;
      case 'contentType':
        indices = enhancedData.classifications.byContentType[value] || [];
        break;
      case 'uncategorized':
        indices = enhancedData.classifications.uncategorized || [];
        break;
      case 'all':
        // Return all requests directly
        sendResponse({ requests: capturedRequests, count: capturedRequests.length });
        return;
    }
    
    // Resolve indices to actual request objects
    const requests = indices.map(index => capturedRequests[index]).filter(r => r !== undefined);
    sendResponse({ requests, count: requests.length });
  }

  if (message.action === "downloadJson") {
    downloadJson(message.filename);
    sendResponse({ status: "downloading" });
  }

  if (message.action === "downloadTxt") {
    downloadTxt(message.filename);
    sendResponse({ status: "downloading" });
  }

  if (message.action === "downloadCategorized") {
    downloadCategorizedFiles(message.filename);
    sendResponse({ status: "downloading categorized files" });
  }

  if (message.action === "sendToHarness") {
    sendCaptureToHarness(message.settings)
      .then((result) => sendResponse({ status: "ok", ...result }))
      .catch((err) => sendResponse({ status: "error", error: String(err.message || err) }));
    return true; // async
  }

  // Handle content script messages
  if (message.action === "webStorageCollected") {
    enhancedData.webStorage = message.data;
    currentSession.webStorage = message.data;
  }

  if (message.action === "domAnalysisComplete") {
    enhancedData.domVulnerabilities = message.vulnerabilities;
    currentSession.domAnalysis = message;
  }

  return true; // Required for async sendResponse
});

// Start periodic storage save only after initialization
function startPeriodicSave() {
  setInterval(() => {
    if (isExtensionReady && capturedRequests.length > 0) {
      try {
        chrome.storage.local.set({
          capturedRequests,
          currentSession: currentSession,
          detectedVulnerabilities: detectedVulnerabilities,
          cloudDetections: cloudDetections,
          enhancedData: enhancedData,
          isCapturing: isCapturing,
        });
      } catch (error) {
        console.error("Error in periodic storage save:", error);
      }
    }
  }, 5000);
}

// Start periodic save after a short delay to ensure initialization is complete
setTimeout(startPeriodicSave, 3000);
