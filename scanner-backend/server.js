const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const net = require("net");

const app = express();
const PORT = process.env.PORT || 10000;

const uploadDir = path.join(__dirname, "uploads");
fs.mkdirSync(uploadDir, { recursive: true });

const upload = multer({
  dest: uploadDir,
  limits: {
    fileSize: 500 * 1024 * 1024,
    files: 1
  }
});

function scanWithClamAV(filePath) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({
      host: process.env.CLAMAV_HOST || "127.0.0.1",
      port: Number(process.env.CLAMAV_PORT || 3310)
    });

    let response = "";

    socket.setTimeout(120000);

    socket.on("connect", () => {
      socket.write("zINSTREAM\0");

      const stream = fs.createReadStream(filePath);

      stream.on("data", (chunk) => {
        const size = Buffer.alloc(4);
        size.writeUInt32BE(chunk.length, 0);

        if (!socket.write(size)) {
          stream.pause();
          socket.once("drain", () => stream.resume());
        }

        socket.write(chunk);
      });

      stream.on("end", () => {
        const end = Buffer.alloc(4);
        end.writeUInt32BE(0, 0);
        socket.write(end);
      });

      stream.on("error", (err) => {
        socket.destroy();
        reject(err);
      });
    });

    socket.on("data", (data) => {
      response += data.toString();
    });

    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error("ClamAV scan timed out."));
    });

    socket.on("error", (err) => {
      reject(err);
    });

    socket.on("close", () => {
      const result = response.trim();

      if (result.endsWith("FOUND")) {
        const match = result.match(/^stream:\s*(.+?)\s+FOUND$/);
        return resolve({
          status: "infected",
          threat: match ? match[1] : "Malware detected"
        });
      }

      if (result.includes("stream: OK")) {
        return resolve({
          status: "clean",
          threat: null
        });
      }

      reject(new Error(result || "Unknown ClamAV response."));
    });
  });
}

app.get("/", (req, res) => {
  res.json({
    service: "SecureFileCrypt Scanner",
    status: "online"
  });
});

app.get("/health", (req, res) => {
  res.json({
    status: "ok"
  });
});

app.post("/scan", upload.single("file"), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({
      error: "No file uploaded."
    });
  }

  const filePath = req.file.path;

  try {
    const result = await scanWithClamAV(filePath);

    res.json({
      engine: "ClamAV",
      filename: req.file.originalname,
      size: req.file.size,
      ...result
    });
  } catch (error) {
    console.error("ClamAV error:", error);

    res.status(503).json({
      engine: "ClamAV",
      filename: req.file.originalname,
      status: "error",
      error: "ClamAV scan failed."
    });
  } finally {
    fs.rmSync(filePath, { force: true });
  }
});

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") {
      return res.status(413).json({
        error: "File is too large."
      });
    }

    return res.status(400).json({
      error: err.message
    });
  }

  console.error(err);

  res.status(500).json({
    error: "Internal server error."
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`SecureFileCrypt scanner listening on port ${PORT}`);
});
