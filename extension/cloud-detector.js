// Cloud Provider Detection Module
// Detects which cloud systems/servers API requests are being made to

console.log("Cloud detector script loaded");

class CloudProviderDetector {
  constructor() {
    this.cloudProviders = {
      aws: {
        name: "Amazon Web Services (AWS)",
        patterns: [
          // AWS API Gateway
          /\.execute-api\.[a-z0-9-]+\.amazonaws\.com/i,
          // AWS Lambda
          /\.lambda\.[a-z0-9-]+\.amazonaws\.com/i,
          // AWS S3
          /\.s3\.[a-z0-9-]+\.amazonaws\.com/i,
          /s3-[a-z0-9-]+\.amazonaws\.com/i,
          /[a-z0-9-]+\.s3\.amazonaws\.com/i,
          // AWS CloudFront
          /\.cloudfront\.net/i,
          // AWS Cognito
          /cognito-idp\.[a-z0-9-]+\.amazonaws\.com/i,
          /cognito-identity\.[a-z0-9-]+\.amazonaws\.com/i,
          // AWS DynamoDB
          /dynamodb\.[a-z0-9-]+\.amazonaws\.com/i,
          // AWS RDS
          /rds\.[a-z0-9-]+\.amazonaws\.com/i,
          // AWS ELB
          /elb\.[a-z0-9-]+\.amazonaws\.com/i,
          // AWS EC2
          /ec2\.[a-z0-9-]+\.amazonaws\.com/i,
          // AWS SQS
          /sqs\.[a-z0-9-]+\.amazonaws\.com/i,
          // AWS SNS
          /sns\.[a-z0-9-]+\.amazonaws\.com/i,
          // AWS CloudWatch
          /monitoring\.[a-z0-9-]+\.amazonaws\.com/i,
          // General AWS
          /amazonaws\.com/i,
        ],
        headers: ["x-amz-", "x-amzn-", "authorization"],
        services: {
          s3: "Simple Storage Service",
          lambda: "Lambda Functions",
          dynamodb: "DynamoDB Database",
          cognito: "User Authentication",
          cloudfront: "Content Delivery Network",
          "execute-api": "API Gateway",
          rds: "Relational Database Service",
          ec2: "Elastic Compute Cloud",
          sqs: "Simple Queue Service",
          sns: "Simple Notification Service",
          monitoring: "CloudWatch",
        },
      },
      azure: {
        name: "Microsoft Azure",
        patterns: [
          // Azure general
          /\.azure\.com/i,
          /\.azurewebsites\.net/i,
          /\.cloudapp\.azure\.com/i,
          /\.blob\.core\.windows\.net/i,
          /\.queue\.core\.windows\.net/i,
          /\.table\.core\.windows\.net/i,
          /\.file\.core\.windows\.net/i,
          // Azure Active Directory
          /login\.microsoftonline\.com/i,
          /graph\.microsoft\.com/i,
          // Azure Functions
          /\.azurewebsites\.net\/api\//i,
          // Azure Cosmos DB
          /\.documents\.azure\.com/i,
          // Azure SQL
          /\.database\.windows\.net/i,
          // Azure Key Vault
          /\.vault\.azure\.net/i,
          // Azure Service Bus
          /\.servicebus\.windows\.net/i,
          // Azure Storage
          /\.core\.windows\.net/i,
          // Azure CDN
          /\.azureedge\.net/i,
          // Azure API Management
          /\.azure-api\.net/i,
        ],
        headers: ["x-ms-", "ocp-apim-", "authorization"],
        services: {
          azurewebsites: "App Service",
          "blob.core.windows": "Blob Storage",
          "documents.azure": "Cosmos DB",
          "database.windows": "SQL Database",
          "vault.azure": "Key Vault",
          "servicebus.windows": "Service Bus",
          "graph.microsoft": "Microsoft Graph API",
          "login.microsoftonline": "Azure Active Directory",
        },
      },
      gcp: {
        name: "Google Cloud Platform (GCP)",
        patterns: [
          // Google Cloud general
          /\.googleapis\.com/i,
          /\.googleapi\.com/i,
          /\.cloudfunctions\.net/i,
          /\.appspot\.com/i,
          /\.run\.app/i,
          // Google Cloud Storage
          /storage\.googleapis\.com/i,
          /\.storage\.googleapis\.com/i,
          // Google Cloud Firestore
          /firestore\.googleapis\.com/i,
          // Google Cloud Functions
          /cloudfunctions\.net/i,
          // Google Cloud Run
          /\.run\.app/i,
          // Google BigQuery
          /bigquery\.googleapis\.com/i,
          // Google Cloud SQL
          /sqladmin\.googleapis\.com/i,
          // Google Cloud Pub/Sub
          /pubsub\.googleapis\.com/i,
          // Google Identity
          /accounts\.google\.com/i,
          /oauth2\.googleapis\.com/i,
          // Google Firebase
          /firebase\.googleapis\.com/i,
          /firebaseio\.com/i,
        ],
        headers: ["x-goog-", "x-firebase-", "authorization"],
        services: {
          "storage.googleapis": "Cloud Storage",
          "firestore.googleapis": "Firestore Database",
          cloudfunctions: "Cloud Functions",
          "run.app": "Cloud Run",
          "bigquery.googleapis": "BigQuery",
          "sqladmin.googleapis": "Cloud SQL",
          "pubsub.googleapis": "Pub/Sub",
          "firebase.googleapis": "Firebase",
          appspot: "App Engine",
        },
      },
      digitalocean: {
        name: "DigitalOcean",
        patterns: [
          /\.digitaloceanspaces\.com/i,
          /\.ondigitalocean\.app/i,
          /api\.digitalocean\.com/i,
        ],
        headers: ["do-", "authorization"],
        services: {
          digitaloceanspaces: "Spaces Object Storage",
          "ondigitalocean.app": "App Platform",
          "api.digitalocean": "API",
        },
      },
      cloudflare: {
        name: "Cloudflare",
        patterns: [
          /\.cloudflarestream\.com/i,
          /\.cloudflareworkers\.com/i,
          /api\.cloudflare\.com/i,
          /\.workers\.dev/i,
        ],
        headers: ["cf-", "x-cf-", "authorization"],
        services: {
          cloudflarestream: "Stream",
          cloudflareworkers: "Workers",
          "workers.dev": "Workers",
          "api.cloudflare": "API",
        },
      },
      heroku: {
        name: "Heroku",
        patterns: [/\.herokuapp\.com/i, /api\.heroku\.com/i],
        headers: ["heroku-", "authorization"],
        services: {
          herokuapp: "App Hosting",
          "api.heroku": "Platform API",
        },
      },
      vercel: {
        name: "Vercel",
        patterns: [/\.vercel\.app/i, /\.vercel\.com/i, /api\.vercel\.com/i],
        headers: ["x-vercel-", "authorization"],
        services: {
          "vercel.app": "App Hosting",
          "api.vercel": "API",
        },
      },
      netlify: {
        name: "Netlify",
        patterns: [/\.netlify\.app/i, /\.netlify\.com/i, /api\.netlify\.com/i],
        headers: ["x-netlify-", "authorization"],
        services: {
          "netlify.app": "App Hosting",
          "api.netlify": "API",
        },
      },
      firebase: {
        name: "Firebase",
        patterns: [
          /\.firebaseio\.com/i,
          /\.firebaseapp\.com/i,
          /firebase\.googleapis\.com/i,
        ],
        headers: ["x-firebase-", "authorization"],
        services: {
          firebaseio: "Realtime Database",
          firebaseapp: "Hosting",
          "firebase.googleapis": "Firebase Services",
        },
      },
      supabase: {
        name: "Supabase",
        patterns: [/\.supabase\.co/i, /\.supabase\.com/i],
        headers: ["apikey", "authorization"],
        services: {
          supabase: "Backend as a Service",
        },
      },
      planetscale: {
        name: "PlanetScale",
        patterns: [/\.psdb\.cloud/i, /api\.planetscale\.com/i],
        headers: ["authorization"],
        services: {
          "psdb.cloud": "Database",
          "api.planetscale": "API",
        },
      },
    };
  }

  /**
   * Detect cloud provider from URL
   * @param {string} url - The request URL
   * @returns {Object|null} - Cloud provider information or null
   */
  detectFromUrl(url) {
    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname.toLowerCase();

      for (const [providerId, provider] of Object.entries(
        this.cloudProviders
      )) {
        for (const pattern of provider.patterns) {
          if (pattern.test(hostname)) {
            // Try to identify specific service
            let detectedService = null;
            for (const [serviceKey, serviceName] of Object.entries(
              provider.services
            )) {
              if (hostname.includes(serviceKey)) {
                detectedService = {
                  key: serviceKey,
                  name: serviceName,
                };
                break;
              }
            }

            return {
              provider: providerId,
              providerName: provider.name,
              hostname: hostname,
              service: detectedService,
              confidence: this.calculateConfidence(hostname, pattern),
              matchedPattern: pattern.source,
            };
          }
        }
      }

      return null;
    } catch (error) {
      console.error("Error detecting cloud provider from URL:", error);
      return null;
    }
  }

  /**
   * Detect cloud provider from request headers
   * @param {Object} headers - Request headers
   * @returns {Array} - Array of potential cloud providers based on headers
   */
  detectFromHeaders(headers) {
    const detectedProviders = [];

    if (!headers) return detectedProviders;

    // Normalize headers to lowercase
    const normalizedHeaders = {};
    Object.keys(headers).forEach((key) => {
      normalizedHeaders[key.toLowerCase()] = headers[key];
    });

    for (const [providerId, provider] of Object.entries(this.cloudProviders)) {
      for (const headerPrefix of provider.headers) {
        for (const headerName of Object.keys(normalizedHeaders)) {
          if (headerName.startsWith(headerPrefix.toLowerCase())) {
            detectedProviders.push({
              provider: providerId,
              providerName: provider.name,
              headerName: headerName,
              headerValue: normalizedHeaders[headerName],
              confidence: 0.8,
            });
          }
        }
      }
    }

    return detectedProviders;
  }

  /**
   * Calculate confidence score for a match
   * @param {string} hostname - The hostname
   * @param {RegExp} pattern - The matched pattern
   * @returns {number} - Confidence score (0-1)
   */
  calculateConfidence(hostname, pattern) {
    // More specific patterns get higher confidence
    const patternSpecificity = pattern.source.length;
    const hostnameLength = hostname.length;

    // Base confidence
    let confidence = 0.7;

    // Increase confidence for more specific patterns
    if (patternSpecificity > 20) confidence += 0.2;
    if (patternSpecificity > 40) confidence += 0.1;

    // Decrease confidence for very generic patterns
    if (pattern.source.includes("amazonaws.com") && patternSpecificity < 20) {
      confidence -= 0.1;
    }

    return Math.min(confidence, 1.0);
  }

  /**
   * Comprehensive cloud detection analysis
   * @param {string} url - Request URL
   * @param {Object} headers - Request headers
   * @param {Object} responseHeaders - Response headers
   * @returns {Object} - Comprehensive cloud analysis
   */
  analyzeRequest(url, headers = {}, responseHeaders = {}) {
    const analysis = {
      url: url,
      timestamp: Date.now(),
      cloudProviders: [],
      summary: {
        isCloudService: false,
        primaryProvider: null,
        confidence: 0,
        services: [],
      },
    };

    // Detect from URL
    const urlDetection = this.detectFromUrl(url);
    if (urlDetection) {
      analysis.cloudProviders.push({
        ...urlDetection,
        detectionMethod: "url",
      });
      analysis.summary.isCloudService = true;
    }

    // Detect from request headers
    const headerDetections = this.detectFromHeaders(headers);
    headerDetections.forEach((detection) => {
      analysis.cloudProviders.push({
        ...detection,
        detectionMethod: "request_headers",
      });
      analysis.summary.isCloudService = true;
    });

    // Detect from response headers
    const responseHeaderDetections = this.detectFromHeaders(responseHeaders);
    responseHeaderDetections.forEach((detection) => {
      analysis.cloudProviders.push({
        ...detection,
        detectionMethod: "response_headers",
      });
      analysis.summary.isCloudService = true;
    });

    // Determine primary provider and calculate overall confidence
    if (analysis.cloudProviders.length > 0) {
      // Group by provider and find the one with highest confidence
      const providerGroups = {};
      analysis.cloudProviders.forEach((detection) => {
        if (!providerGroups[detection.provider]) {
          providerGroups[detection.provider] = {
            provider: detection.provider,
            providerName: detection.providerName,
            detections: [],
            maxConfidence: 0,
            services: new Set(),
          };
        }

        providerGroups[detection.provider].detections.push(detection);
        providerGroups[detection.provider].maxConfidence = Math.max(
          providerGroups[detection.provider].maxConfidence,
          detection.confidence || 0.5
        );

        if (detection.service) {
          providerGroups[detection.provider].services.add(
            detection.service.name
          );
        }
      });

      // Find primary provider (highest confidence)
      let primaryProvider = null;
      let maxConfidence = 0;

      Object.values(providerGroups).forEach((group) => {
        if (group.maxConfidence > maxConfidence) {
          maxConfidence = group.maxConfidence;
          primaryProvider = group;
        }
      });

      if (primaryProvider) {
        analysis.summary.primaryProvider = {
          provider: primaryProvider.provider,
          providerName: primaryProvider.providerName,
          confidence: primaryProvider.maxConfidence,
          detectionCount: primaryProvider.detections.length,
          services: Array.from(primaryProvider.services),
        };
        analysis.summary.confidence = primaryProvider.maxConfidence;
        analysis.summary.services = Array.from(primaryProvider.services);
      }
    }

    return analysis;
  }

  /**
   * Get statistics about detected cloud providers
   * @param {Array} detections - Array of cloud detection results
   * @returns {Object} - Statistics summary
   */
  getStatistics(detections) {
    const stats = {
      totalRequests: detections.length,
      cloudRequests: 0,
      providers: {},
      services: {},
      topProvider: null,
      cloudPercentage: 0,
    };

    detections.forEach((detection) => {
      if (detection.summary.isCloudService) {
        stats.cloudRequests++;

        if (detection.summary.primaryProvider) {
          const provider = detection.summary.primaryProvider.provider;
          const providerName = detection.summary.primaryProvider.providerName;

          if (!stats.providers[provider]) {
            stats.providers[provider] = {
              name: providerName,
              count: 0,
              services: new Set(),
            };
          }

          stats.providers[provider].count++;

          // Add services
          detection.summary.services.forEach((service) => {
            stats.providers[provider].services.add(service);

            if (!stats.services[service]) {
              stats.services[service] = 0;
            }
            stats.services[service]++;
          });
        }
      }
    });

    // Calculate cloud percentage
    stats.cloudPercentage =
      stats.totalRequests > 0
        ? ((stats.cloudRequests / stats.totalRequests) * 100).toFixed(1)
        : 0;

    // Find top provider
    let maxCount = 0;
    Object.entries(stats.providers).forEach(([provider, data]) => {
      if (data.count > maxCount) {
        maxCount = data.count;
        stats.topProvider = {
          provider: provider,
          name: data.name,
          count: data.count,
          services: Array.from(data.services),
        };
      }
    });

    // Convert services Sets to Arrays
    Object.values(stats.providers).forEach((provider) => {
      provider.services = Array.from(provider.services);
    });

    return stats;
  }
}

console.log("CloudProviderDetector class defined");

// Export for use in background script - compatible with service workers
if (typeof module !== "undefined" && module.exports) {
  module.exports = CloudProviderDetector;
  console.log("Exported CloudProviderDetector via module.exports");
} else if (typeof window !== "undefined") {
  // Browser environment
  window.CloudProviderDetector = CloudProviderDetector;
  console.log("Exported CloudProviderDetector to window");
} else if (typeof globalThis !== "undefined") {
  // Service Worker environment
  globalThis.CloudProviderDetector = CloudProviderDetector;
  console.log("Exported CloudProviderDetector to globalThis");
} else if (typeof self !== "undefined") {
  // Alternative service worker reference
  self.CloudProviderDetector = CloudProviderDetector;
  console.log("Exported CloudProviderDetector to self");
}

console.log("Cloud detector module loaded completely");
