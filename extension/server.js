const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const app = express();
const port = 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Create captures directory if it doesn't exist
const capturesDir = path.join(__dirname, "captures");
if (!fs.existsSync(capturesDir)) {
  fs.mkdirSync(capturesDir);
}

// Endpoint to receive captured requests
app.post("/upload", (req, res) => {
  try {
    const { site, timestamp, data, url } = req.body;

    if (!site || !timestamp || !data) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    // Create a filename based on site and timestamp
    const filename = `${site}_${timestamp.replace(/[:.]/g, "-")}.json`;
    const filepath = path.join(capturesDir, filename);

    // Save the captured data
    const captureData = {
      site,
      timestamp,
      url,
      requestCount: data.length,
      requests: data,
    };

    fs.writeFileSync(filepath, JSON.stringify(captureData, null, 2));

    console.log(`Saved capture data to ${filename}`);
    res.json({
      success: true,
      message: "Capture data saved successfully",
      filename,
    });
  } catch (error) {
    console.error("Error saving capture data:", error);
    res.status(500).json({
      error: "Failed to save capture data",
      details: error.message,
    });
  }
});

// Endpoint to list all captures
app.get("/captures", (req, res) => {
  try {
    const files = fs
      .readdirSync(capturesDir)
      .filter((file) => file.endsWith(".json"))
      .map((file) => {
        const stats = fs.statSync(path.join(capturesDir, file));
        return {
          filename: file,
          size: stats.size,
          created: stats.birthtime,
        };
      });

    res.json({ captures: files });
  } catch (error) {
    console.error("Error listing captures:", error);
    res.status(500).json({ error: "Failed to list captures" });
  }
});

// Start server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
