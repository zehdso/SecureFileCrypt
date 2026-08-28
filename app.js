const encryptFile = document.getElementById("encryptFile");
const decryptFile = document.getElementById("decryptFile");

const encryptPassword = document.getElementById("encryptPassword");
const decryptPassword = document.getElementById("decryptPassword");

const generatePasswordButton = document.getElementById("generatePassword");
const copyPasswordButton = document.getElementById("copyPassword");
const passwordStrength = document.getElementById("passwordStrength");
const passwordStrengthFill = document.getElementById("passwordStrengthFill");
const passwordStrengthText = document.getElementById("passwordStrengthText");

const encryptButton = document.getElementById("encryptButton");
const scanButton = document.getElementById("scanButton");
const decryptButton = document.getElementById("decryptButton");

const encryptStatus = document.getElementById("encryptStatus");

const scanStatus = document.getElementById("scanStatus");
const scanProgressContainer = document.getElementById("scanProgressContainer");
const scanProgress = document.getElementById("scanProgress");
const scanProgressText = document.getElementById("scanProgressText");
const SCANNER_URL = "https://securefilecrypt.onrender.com";
const decryptStatus = document.getElementById("decryptStatus");

const encryptResult = document.getElementById("encryptResult");
const decryptResult = document.getElementById("decryptResult");

const encryptResultName = document.getElementById("encryptResultName");
const decryptResultName = document.getElementById("decryptResultName");

const encryptResultSize = document.getElementById("encryptResultSize");
const decryptResultSize = document.getElementById("decryptResultSize");

const encryptDownload = document.getElementById("encryptDownload");
const encryptZipDownload = document.getElementById("encryptZipDownload");
const decryptDownload = document.getElementById("decryptDownload");

const encryptTab = document.getElementById("encryptTab");
const decryptTab = document.getElementById("decryptTab");

const encryptPage = document.getElementById("encryptPage");
const decryptPage = document.getElementById("decryptPage");

const warningModal = document.getElementById("warningModal");
const closeWarning = document.getElementById("closeWarning");

const OLD_MAGIC = "SFC1";
const OLD_CHUNK_MAGIC = "SFC2";
const MAGIC = new TextEncoder().encode("SFC4");

const SALT_SIZE = 16;
const IV_SIZE = 12;
const CHUNK_SIZE = 4 * 1024 * 1024;

const ARGON2_TIME = 3;
const ARGON2_MEMORY = 65536;
const ARGON2_PARALLELISM = 1;
const ARGON2_HASH_LENGTH = 32;

let pendingEncryptDownload = null;
let pendingDecryptDownload = null;

function getPasswordStrength(password) {
  if (!password) {
    return { score: 0, text: "", width: "0%" };
  }

  let score = 0;

  if (password.length >= 12) score++;
  if (password.length >= 16) score++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
  if (/\\d/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;

  if (score <= 1) {
    return { score, text: "Weak", width: "20%" };
  }

  if (score === 2) {
    return { score, text: "Fair", width: "40%" };
  }

  if (score === 3) {
    return { score, text: "Good", width: "60%" };
  }

  if (score === 4) {
    return { score, text: "Strong", width: "80%" };
  }

  return { score, text: "Very strong", width: "100%" };
}

function updatePasswordStrength() {
  if (!passwordStrength || !passwordStrengthFill || !passwordStrengthText) {
    return;
  }

  const result = getPasswordStrength(encryptPassword.value);

  if (!encryptPassword.value) {
    passwordStrength.classList.add("hidden");
    passwordStrengthFill.style.width = "0%";
    passwordStrengthText.textContent = "";
    return;
  }

  passwordStrength.classList.remove("hidden");
  passwordStrengthFill.style.width = result.width;
  passwordStrengthText.textContent = result.text;
}

function generateStrongPassword(length = 20) {
  const alphabet =
    "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+";

  const values = new Uint32Array(length);
  crypto.getRandomValues(values);

  let password = "";

  for (let i = 0; i < values.length; i++) {
    password += alphabet[values[i] % alphabet.length];
  }

  return password;
}

if (encryptPassword) {
  encryptPassword.addEventListener("input", updatePasswordStrength);
}

if (generatePasswordButton) {
  generatePasswordButton.addEventListener("click", () => {
    encryptPassword.value = generateStrongPassword();
    encryptPassword.type = "text";

    document
      .querySelectorAll('.toggle-password[data-target="encryptPassword"]')
      .forEach(button => {
        button.classList.add("is-visible");
        button.setAttribute("aria-label", "Hide password");
      });

    updatePasswordStrength();
  });
}

if (copyPasswordButton) {
  copyPasswordButton.addEventListener("click", async () => {
    if (!encryptPassword.value) {
      generatePasswordButton.click();
    }

    try {
      await navigator.clipboard.writeText(encryptPassword.value);
      copyPasswordButton.textContent = "Copied";

      setTimeout(() => {
        copyPasswordButton.textContent = "Copy";
      }, 1500);
    } catch {
      copyPasswordButton.textContent = "Copy failed";

      setTimeout(() => {
        copyPasswordButton.textContent = "Copy";
      }, 1500);
    }
  });
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;

  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = -1;

  do {
    value /= 1024;
    unit++;
  } while (value >= 1024 && unit < units.length - 1);

  return `${value.toFixed(value >= 100 ? 0 : 1)} ${units[unit]}`;
}

async function deriveArgon2Key(password, salt) {
  if (typeof argon2 === "undefined") {
    throw new Error("Argon2 library is not loaded.");
  }

  const result = await argon2.hash({
    pass: password,
    salt,
    type: argon2.ArgonType.Argon2id,
    time: ARGON2_TIME,
    mem: ARGON2_MEMORY,
    parallelism: ARGON2_PARALLELISM,
    hashLen: ARGON2_HASH_LENGTH
  });

  return crypto.subtle.importKey(
    "raw",
    result.hash,
    {
      name: "AES-GCM",
      length: 256
    },
    false,
    ["encrypt", "decrypt"]
  );
}

async function derivePBKDF2Key(password, salt) {
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 600000,
      hash: "SHA-256"
    },
    passwordKey,
    {
      name: "AES-GCM",
      length: 256
    },
    false,
    ["encrypt", "decrypt"]
  );
}

function createChunkIv(baseIv, counter) {
  if (
    !Number.isSafeInteger(counter) ||
    counter < 0 ||
    counter > 0xFFFFFFFF
  ) {
    throw new Error("Chunk counter exceeds AES-GCM IV limit.");
  }

  const iv = new Uint8Array(baseIv);
  const view = new DataView(iv.buffer);

  view.setUint32(8, counter, false);

  return iv;
}

function writeUint32(value) {
  const buffer = new ArrayBuffer(4);

  new DataView(buffer).setUint32(
    0,
    value,
    true
  );

  return new Uint8Array(buffer);
}

function writeUint64(value) {
  const buffer = new ArrayBuffer(8);

  new DataView(buffer).setBigUint64(
    0,
    BigInt(value),
    true
  );

  return new Uint8Array(buffer);
}

function readUint32(data, offset) {
  return new DataView(
    data.buffer,
    data.byteOffset + offset,
    4
  ).getUint32(0, true);
}

function readUint64(data, offset) {
  const value =
    new DataView(
      data.buffer,
      data.byteOffset + offset,
      8
    ).getBigUint64(0, true);

  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("File size exceeds the supported limit.");
  }

  return Number(value);
}

function prepareDownload(blob, filename) {
  return {
    blob,
    url: URL.createObjectURL(blob),
    filename
  };
}

function showResult(
  resultElement,
  nameElement,
  sizeElement,
  blob,
  filename,
  type
) {
  const download = prepareDownload(
    blob,
    filename
  );

  nameElement.textContent = filename;
  sizeElement.textContent =
    formatBytes(blob.size);

  resultElement.classList.remove("hidden");

  if (type === "encrypt") {
    pendingEncryptDownload = download;
  } else {
    pendingDecryptDownload = download;
  }
}

if (encryptDownload) {
  encryptDownload.addEventListener("click", () => {
    downloadPending(pendingEncryptDownload);
  });
}

if (decryptDownload) {
  decryptDownload.addEventListener("click", () => {
    downloadPending(pendingDecryptDownload);
  });
}

if (encryptZipDownload) {
  encryptZipDownload.addEventListener("click", async () => {
    if (!pendingEncryptDownload?.blob) return;

    if (typeof JSZip === "undefined") {
      console.error("JSZip is not available.");
      return;
    }

    const zip = new JSZip();

    zip.file(
      pendingEncryptDownload.filename,
      pendingEncryptDownload.blob
    );

    zip.file(
      "password.txt",
      encryptPassword.value
    );

    const zipBlob = await zip.generateAsync({
      type: "blob",
      compression: "DEFLATE",
      compressionOptions: {
        level: 6
      }
    });

    const url = URL.createObjectURL(zipBlob);
    const link = document.createElement("a");

    link.href = url;
    link.download =
      pendingEncryptDownload.filename + ".zip";

    document.body.appendChild(link);
    link.click();
    link.remove();

    setTimeout(() => URL.revokeObjectURL(url), 2000);
  });
}

function downloadPending(download) {
  if (!download || !download.blob) return;

  const url = URL.createObjectURL(download.blob);
  const link = document.createElement("a");

  const dot = download.filename.lastIndexOf(".");
  const base = dot > 0 ? download.filename.slice(0, dot) : download.filename;
  const ext = dot > 0 ? download.filename.slice(dot) : "";

  download.counter = (download.counter || 0) + 1;

  link.href = url;
  link.download =
    download.counter === 1
      ? download.filename
      : `${base} (${download.counter})${ext}`;

  document.body.appendChild(link);
  link.click();
  link.remove();

  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

async function decryptSFC1(data, password) {
  let offset = 0;

  const magic = new TextDecoder().decode(
    data.slice(offset, offset + 4)
  );

  offset += 4;

  if (magic !== OLD_MAGIC) {
    throw new Error("Invalid SFC1 file.");
  }

  const salt = data.slice(
    offset,
    offset + SALT_SIZE
  );

  offset += SALT_SIZE;

  const iv = data.slice(
    offset,
    offset + IV_SIZE
  );

  offset += IV_SIZE;

  const nameLength =
    readUint32(data, offset);

  offset += 4;

  const originalName =
    new TextDecoder().decode(
      data.slice(
        offset,
        offset + nameLength
      )
    );

  offset += nameLength;

  const encrypted = data.slice(offset);

  const key = await derivePBKDF2Key(
    password,
    salt
  );

  const decrypted =
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv
      },
      key,
      encrypted
    );

  return {
    blob: new Blob([decrypted]),
    filename: originalName
  };
}

async function decryptSFC2(data, password) {
  let offset = 4;

  const salt = data.slice(
    offset,
    offset + SALT_SIZE
  );

  offset += SALT_SIZE;

  const baseIv = data.slice(
    offset,
    offset + IV_SIZE
  );

  offset += IV_SIZE;

  const nameLength =
    readUint32(data, offset);

  offset += 4;

  const chunkSize =
    readUint32(data, offset);

  offset += 4;

  const originalSize =
    readUint64(data, offset);

  offset += 8;

  if (
    chunkSize === 0 ||
    chunkSize > 64 * 1024 * 1024
  ) {
    throw new Error(
      "Invalid chunk size."
    );
  }

  const originalName =
    new TextDecoder().decode(
      data.slice(
        offset,
        offset + nameLength
      )
    );

  offset += nameLength;

  const key = await derivePBKDF2Key(
    password,
    salt
  );

  const chunkCount = Math.ceil(
    originalSize / chunkSize
  );

  const decryptedChunks = [];

  for (
    let index = 0;
    index < chunkCount;
    index++
  ) {
    const plaintextSize =
      index === chunkCount - 1
        ? originalSize -
          index * chunkSize
        : chunkSize;

    const encryptedSize =
      plaintextSize + 16;

    if (
      offset + encryptedSize >
      data.length
    ) {
      throw new Error(
        "Encrypted file is incomplete."
      );
    }

    const encrypted =
      data.slice(
        offset,
        offset + encryptedSize
      );

    offset += encryptedSize;

    const iv = createChunkIv(
      baseIv,
      index
    );

    const decrypted =
      await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv
        },
        key,
        encrypted
      );

    decryptedChunks.push(
      new Uint8Array(decrypted)
    );

    const percent = Math.round(
      ((index + 1) / chunkCount) * 100
    );

    decryptStatus.textContent =
      `Decrypting... ${percent}%`;

    await new Promise(
      resolve => setTimeout(resolve, 0)
    );
  }

  return {
    blob: new Blob(decryptedChunks),
    filename: originalName
  };
}

scanButton.addEventListener("click", async () => {
  const file = encryptFile.files[0];

  if (!file) {
    scanStatus.textContent = "Scan: no file selected.";
    return;
  }

  const pauseScanButton = document.getElementById("pauseScanButton");
  const CHUNK_SIZE = 5 * 1024 * 1024;

  scanButton.disabled = true;
  pauseScanButton.classList.remove("hidden");
  pauseScanButton.textContent = "Pause Upload";
  scanProgressContainer.classList.remove("hidden");
  scanProgress.value = 0;
  scanProgressText.textContent = "0%";

  let uploadId = null;
  let offset = 0;
  let paused = false;

  try {
    const sizeMB = (file.size / (1024 * 1024)).toFixed(2);

    scanStatus.textContent =
      `Scan 1/4: Selected "${file.name}" (${sizeMB} MB).`;

    const startResponse = await fetch(`${SCANNER_URL}/upload/start`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        filename: file.name,
        size: file.size
      })
    });

    if (!startResponse.ok) {
      throw new Error("Could not start upload.");
    }

    const startResult = await startResponse.json();
    uploadId = startResult.upload_id;
    offset = startResult.offset || 0;

    scanStatus.textContent =
      "Scan 2/4: Uploading file...";

    pauseScanButton.onclick = () => {
      paused = !paused;
      pauseScanButton.textContent =
        paused ? "Resume Upload" : "Pause Upload";

      scanStatus.textContent =
        paused
          ? "Scan 3/4: Upload paused."
          : "Scan 3/4: Upload resumed.";
    };

    while (offset < file.size) {
      while (paused) {
        await new Promise(resolve => setTimeout(resolve, 200));
      }

      const end = Math.min(offset + CHUNK_SIZE, file.size);
      const chunk = file.slice(offset, end);

      const response = await fetch(`${SCANNER_URL}/upload/chunk`, {
        method: "POST",
        headers: {
          "Content-Type": "application/octet-stream",
          "X-Upload-ID": uploadId,
          "X-Upload-Offset": String(offset)
        },
        body: chunk
      });

      if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new Error(error.error || `Upload failed (${response.status}).`);
      }

      const result = await response.json();
      offset = result.offset;

      const percent = Math.round((offset / file.size) * 100);
      const loadedMB = (offset / (1024 * 1024)).toFixed(2);
      const totalMB = (file.size / (1024 * 1024)).toFixed(2);

      scanProgress.value = percent;
      scanProgressText.textContent =
        `${percent}% (${loadedMB} / ${totalMB} MB)`;

      scanStatus.textContent =
        `Scan 3/4: Uploading file... ${percent}%`;
    }

    pauseScanButton.classList.add("hidden");

    scanStatus.textContent =
      "Scan 4/4: YARA-X is analyzing the uploaded file...";

    const scanResponse = await fetch(`${SCANNER_URL}/scan-upload`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        upload_id: uploadId,
        filename: file.name
      })
    });

    if (!scanResponse.ok) {
      throw new Error(`Scanner returned HTTP ${scanResponse.status}`);
    }

    const result = await scanResponse.json();

    if (result.status === "suspicious") {
      scanStatus.textContent =
        `Scan 4/4: SUSPICIOUS — ${result.matches.join(", ") || "threat detected"}.`;
      return;
    }

    if (result.status === "no_match") {
      scanStatus.textContent =
        "Scan 4/4: CLEAN — YARA-X found no matching rules.";
      return;
    }

    throw new Error(result.error || "Unexpected scanner response.");

  } catch (error) {
    console.error("Scan error:", error);
    scanStatus.textContent =
      `Scan failed: ${error.message}`;
  } finally {
    scanButton.disabled = false;
    pauseScanButton.classList.add("hidden");
  }
});

encryptButton.addEventListener(
  "click",
  async () => {
    try {
      const file =
        encryptFile.files[0];

      const password =
        encryptPassword.value;

      encryptResult.classList.add(
        "hidden"
      );

      if (!file) {
        encryptStatus.textContent =
          "Select a file first.";
        return;
      }

      if (!password) {
        encryptStatus.textContent =
          "Enter a password.";
        return;
      }

      encryptButton.disabled = true;

      encryptStatus.textContent =
        "Deriving secure key...";

      const salt =
        crypto.getRandomValues(
          new Uint8Array(SALT_SIZE)
        );

      const baseIv =
        crypto.getRandomValues(
          new Uint8Array(IV_SIZE)
        );

      const key =
        await deriveArgon2Key(
          password,
          salt
        );

      const originalName =
        new TextEncoder().encode(
          file.name
        );

      /*
       * SFC4 metadata:
       * filename + original size + chunk size
       * are encrypted and authenticated.
       *
       * The filename is therefore never stored
       * in plaintext inside the SFC4 file.
       */
      const metadataIv =
        crypto.getRandomValues(
          new Uint8Array(IV_SIZE)
        );

      const metadataPlaintext = new Uint8Array(
        4 +
        4 +
        8 +
        originalName.length
      );

      let metadataOffset = 0;

      metadataPlaintext.set(
        writeUint32(originalName.length),
        metadataOffset
      );

      metadataOffset += 4;

      metadataPlaintext.set(
        writeUint32(CHUNK_SIZE),
        metadataOffset
      );

      metadataOffset += 4;

      metadataPlaintext.set(
        writeUint64(file.size),
        metadataOffset
      );

      metadataOffset += 8;

      metadataPlaintext.set(
        originalName,
        metadataOffset
      );

      const encryptedMetadata =
        new Uint8Array(
          await crypto.subtle.encrypt(
            {
              name: "AES-GCM",
              iv: metadataIv
            },
            key,
            metadataPlaintext
          )
        );

      const header = [
        MAGIC,
        salt,
        baseIv,
        metadataIv,
        writeUint32(
          encryptedMetadata.length
        ),
        encryptedMetadata
      ];

      const encryptedChunks = [];

      const chunkCount =
        Math.ceil(
          file.size / CHUNK_SIZE
        );

      for (
        let index = 0;
        index < chunkCount;
        index++
      ) {
        const start =
          index * CHUNK_SIZE;

        const end = Math.min(
          start + CHUNK_SIZE,
          file.size
        );

        const chunk =
          await file
            .slice(start, end)
            .arrayBuffer();

        const iv =
          createChunkIv(
            baseIv,
            index
          );

        const encrypted =
          await crypto.subtle.encrypt(
            {
              name: "AES-GCM",
              iv
            },
            key,
            chunk
          );

        encryptedChunks.push(
          new Uint8Array(encrypted)
        );

        const percent =
          Math.round(
            ((index + 1) /
              chunkCount) *
              100
          );

        encryptStatus.textContent =
          `Encrypting... ${percent}%`;

        await new Promise(
          resolve =>
            setTimeout(resolve, 0)
        );
      }

      const output = new Blob(
        [
          ...header,
          ...encryptedChunks
        ],
        {
          type:
            "application/octet-stream"
        }
      );

        const baseName =
          file.name.includes(".")
            ? file.name.substring(
                0,
                file.name.lastIndexOf(".")
              )
            : file.name;

        let selectedExtension =
          encryptExtension?.value || ".sfc4";

        if (selectedExtension === "none") {
          selectedExtension = "";
        } else if (selectedExtension === "custom") {
          selectedExtension =
            customExtension?.value.trim() || ".sfc4";

          if (!selectedExtension.startsWith(".")) {
            selectedExtension = "." + selectedExtension;
          }
        }

        const encryptedName =
          baseName + selectedExtension;

        showResult(
          encryptResult,
          encryptResultName,
          encryptResultSize,
          output,
          encryptedName,
          "encrypt"
        );

        encryptStatus.textContent =
          "Encryption complete.";

        if (selectedExtension === "") {
          warningModal.classList.remove(
            "hidden"
          );
        }
      } catch (error) {
        console.error(error);

        encryptStatus.textContent =
          "Encryption failed.";
      } finally {
        encryptButton.disabled = false;
      }
    }
  );

decryptButton.addEventListener(
  "click",
  async () => {
    try {
      const file =
        decryptFile.files[0];

      const password =
        decryptPassword.value;

      decryptResult.classList.add(
        "hidden"
      );

      if (!file) {
        decryptStatus.textContent =
          "Select an encrypted file first.";
        return;
      }

      if (!password) {
        decryptStatus.textContent =
          "Enter a password.";
        return;
      }

      decryptButton.disabled = true;

      decryptStatus.textContent =
        "Reading encrypted file...";

      const data =
        new Uint8Array(
          await file.arrayBuffer()
        );

      const magic =
        new TextDecoder().decode(
          data.slice(0, 4)
        );

      let result;

      if (magic === OLD_MAGIC) {
        result =
          await decryptSFC1(
            data,
            password
          );
      } else if (
        magic === OLD_CHUNK_MAGIC
      ) {
        result =
          await decryptSFC2(
            data,
            password
          );
      } else if (
        magic === "SFC4"
      ) {
        let offset = 4;

        const salt =
          data.slice(
            offset,
            offset + SALT_SIZE
          );

        offset += SALT_SIZE;

        const baseIv =
          data.slice(
            offset,
            offset + IV_SIZE
          );

        offset += IV_SIZE;

        const metadataIv =
          data.slice(
            offset,
            offset + IV_SIZE
          );

        offset += IV_SIZE;

        const metadataLength =
          readUint32(
            data,
            offset
          );

        offset += 4;

        if (
          metadataLength < 16 ||
          metadataLength > 16 * 1024 * 1024 ||
          offset + metadataLength > data.length
        ) {
          throw new Error(
            "Invalid encrypted metadata."
          );
        }

        const encryptedMetadata =
          data.slice(
            offset,
            offset + metadataLength
          );

        offset += metadataLength;

        decryptStatus.textContent =
          "Deriving secure key...";

        const key =
          await deriveArgon2Key(
            password,
            salt
          );

        let metadata;

        try {
          metadata =
            new Uint8Array(
              await crypto.subtle.decrypt(
                {
                  name: "AES-GCM",
                  iv: metadataIv
                },
                key,
                encryptedMetadata
              )
            );
        } catch {
          throw new Error(
            "Incorrect password or corrupted file."
          );
        }

        if (metadata.length < 16) {
          throw new Error(
            "Invalid encrypted metadata."
          );
        }

        let metadataOffset = 0;

        const nameLength =
          readUint32(
            metadata,
            metadataOffset
          );

        metadataOffset += 4;

        const chunkSize =
          readUint32(
            metadata,
            metadataOffset
          );

        metadataOffset += 4;

        const originalSize =
          readUint64(
            metadata,
            metadataOffset
          );

        metadataOffset += 8;

        if (
          nameLength > metadata.length - metadataOffset
        ) {
          throw new Error(
            "Invalid filename metadata."
          );
        }

        if (
          chunkSize === 0 ||
          chunkSize >
            64 * 1024 * 1024
        ) {
          throw new Error(
            "Invalid chunk size."
          );
        }

        const originalName =
          new TextDecoder().decode(
            metadata.slice(
              metadataOffset,
              metadataOffset + nameLength
            )
          );

        metadataOffset += nameLength;

        if (
          metadataOffset !== metadata.length
        ) {
          throw new Error(
            "Invalid encrypted metadata."
          );
        }

        if (
          !Number.isSafeInteger(originalSize) ||
          originalSize < 0
        ) {
          throw new Error(
            "Invalid original file size."
          );
        }

        if (
          originalSize === 0
        ) {
          if (offset !== data.length) {
            throw new Error(
              "Invalid encrypted file."
            );
          }

          result = {
            blob: new Blob(),
            filename: originalName
          };

          decryptStatus.textContent =
            "Decryption complete.";

          return;
        }

        const chunkCount =
          Math.ceil(
            originalSize /
              chunkSize
          );

        if (
          chunkCount < 1 ||
          chunkCount > 0x100000000
        ) {
          throw new Error(
            "File contains too many encrypted chunks."
          );
        }

        const decryptedChunks = [];

        for (
          let index = 0;
          index < chunkCount;
          index++
        ) {
          const plaintextSize =
            index ===
            chunkCount - 1
              ? originalSize -
                index * chunkSize
              : chunkSize;

          const encryptedSize =
            plaintextSize + 16;

          if (
            offset +
              encryptedSize >
            data.length
          ) {
            throw new Error(
              "Encrypted file is incomplete."
            );
          }

          const encrypted =
            data.slice(
              offset,
              offset +
                encryptedSize
            );

          offset += encryptedSize;

          const iv =
            createChunkIv(
              baseIv,
              index
            );

          const decrypted =
            await crypto.subtle.decrypt(
              {
                name: "AES-GCM",
                iv
              },
              key,
              encrypted
            );

          decryptedChunks.push(
            new Uint8Array(
              decrypted
            )
          );

          const percent =
            Math.round(
              ((index + 1) /
                chunkCount) *
                100
            );

          decryptStatus.textContent =
            `Decrypting... ${percent}%`;

          await new Promise(
            resolve =>
              setTimeout(
                resolve,
                0
              )
          );
        }

        if (
          offset !== data.length
        ) {
          throw new Error(
            "Invalid encrypted file."
          );
        }

        result = {
          blob: new Blob(
            decryptedChunks
          ),
          filename:
            originalName
        };
      } else if (
        magic === "SFC3"
      ) {
        let offset = 4;

        const salt =
          data.slice(
            offset,
            offset + SALT_SIZE
          );

        offset += SALT_SIZE;

        const baseIv =
          data.slice(
            offset,
            offset + IV_SIZE
          );

        offset += IV_SIZE;

        const nameLength =
          readUint32(
            data,
            offset
          );

        offset += 4;

        const chunkSize =
          readUint32(
            data,
            offset
          );

        offset += 4;

        const originalSize =
          readUint64(
            data,
            offset
          );

        offset += 8;

        if (
          chunkSize === 0 ||
          chunkSize >
            64 * 1024 * 1024
        ) {
          throw new Error(
            "Invalid chunk size."
          );
        }

        const originalName =
          new TextDecoder().decode(
            data.slice(
              offset,
              offset + nameLength
            )
          );

        offset += nameLength;

        decryptStatus.textContent =
          "Deriving secure key...";

        const key =
          await deriveArgon2Key(
            password,
            salt
          );

        const chunkCount =
          Math.ceil(
            originalSize /
              chunkSize
          );

        const decryptedChunks = [];

        for (
          let index = 0;
          index < chunkCount;
          index++
        ) {
          const plaintextSize =
            index ===
            chunkCount - 1
              ? originalSize -
                index * chunkSize
              : chunkSize;

          const encryptedSize =
            plaintextSize + 16;

          if (
            offset +
              encryptedSize >
            data.length
          ) {
            throw new Error(
              "Encrypted file is incomplete."
            );
          }

          const encrypted =
            data.slice(
              offset,
              offset +
                encryptedSize
            );

          offset += encryptedSize;

          const iv =
            createChunkIv(
              baseIv,
              index
            );

          const decrypted =
            await crypto.subtle.decrypt(
              {
                name: "AES-GCM",
                iv
              },
              key,
              encrypted
            );

          decryptedChunks.push(
            new Uint8Array(
              decrypted
            )
          );

          const percent =
            Math.round(
              ((index + 1) /
                chunkCount) *
                100
            );

          decryptStatus.textContent =
            `Decrypting... ${percent}%`;

          await new Promise(
            resolve =>
              setTimeout(
                resolve,
                0
              )
          );
        }

        if (
          offset !== data.length
        ) {
          throw new Error(
            "Invalid encrypted file."
          );
        }

        result = {
          blob: new Blob(
            decryptedChunks
          ),
          filename:
            originalName
        };
      } else {
        throw new Error(
          "Invalid SecureFileCrypt file."
        );
      }

      showResult(
        decryptResult,
        decryptResultName,
        decryptResultSize,
        result.blob,
        result.filename,
        "decrypt"
      );

      decryptStatus.textContent =
        "Decryption complete.";
    } catch (error) {
      console.error(error);

      decryptStatus.textContent =
        "Decryption failed: wrong password or invalid file.";
    } finally {
      decryptButton.disabled = false;
    }
  }
);

encryptTab.addEventListener(
  "click",
  () => {
    encryptTab.classList.add("active");
    decryptTab.classList.remove("active");

    encryptPage.classList.remove(
      "hidden"
    );

    decryptPage.classList.add(
      "hidden"
    );
  }
);

decryptTab.addEventListener(
  "click",
  () => {
    decryptTab.classList.add("active");
    encryptTab.classList.remove("active");

    decryptPage.classList.remove(
      "hidden"
    );

    encryptPage.classList.add(
      "hidden"
    );
  }
);



closeWarning.addEventListener(
  "click",
  () => {
    warningModal.classList.add(
      "hidden"
    );
  }
);

warningModal.addEventListener(
  "click",
  event => {
    if (
      event.target === warningModal
    ) {
      warningModal.classList.add(
        "hidden"
      );
    }
  }
);



document
  .querySelectorAll(".toggle-password")
  .forEach(button => {
    button.addEventListener("click", () => {
      const input =
        document.getElementById(
          button.dataset.target
        );

      const visible =
        input.type === "text";

      input.type =
        visible ? "password" : "text";

      button.classList.toggle(
        "is-visible",
        !visible
      );

      button.setAttribute(
        "aria-label",
        visible
          ? "Show password"
          : "Hide password"
      );
    });
  });

function formatFileModified(date) {
  if (!date) return "—";

  return new Date(date).toLocaleString([], {
    dateStyle: "medium",
    timeStyle: "short"
  });
}

function showFileMetadata(file, type) {
  if (!file) return;

  const prefix = type === "encrypt"
    ? "encrypt"
    : "decrypt";

  const panel =
    document.getElementById(`${prefix}Metadata`);

  const name =
    document.getElementById(`${prefix}MetaName`);

  const fileType =
    document.getElementById(`${prefix}MetaType`);

  const size =
    document.getElementById(`${prefix}MetaSize`);

  const modified =
    document.getElementById(`${prefix}MetaModified`);

  if (!panel) return;

  if (name) name.textContent = file.name || "—";

  if (fileType) {
    fileType.textContent =
      file.type || "Unknown";
  }

  if (size) {
    size.textContent =
      formatBytes(file.size);
  }

  if (modified) {
    modified.textContent =
      formatFileModified(file.lastModified);
  }

  panel.classList.remove("hidden");
}

if (encryptFile) {
  encryptFile.addEventListener("change", () => {
    const file = encryptFile.files[0];
    const sensitiveSection =
      document.getElementById("encryptSensitiveSection");

    showFileMetadata(file, "encrypt");

    if (sensitiveSection) {
      sensitiveSection.classList.toggle("hidden", !file);
    }
  });
}

if (decryptFile) {
  decryptFile.addEventListener("change", () => {
    showFileMetadata(
      decryptFile.files[0],
      "decrypt"
    );
  });
}

if (encryptFile) {
  encryptFile.addEventListener("change", () => {
    const file = encryptFile.files[0];
    const panel =
      document.getElementById("encryptSensitivePanel");

    if (panel) {
      panel.classList.add("hidden");
    }
  });
}

const encryptSensitiveMetadata =
  document.getElementById(
    "encryptSensitiveMetadata"
  );

const encryptSensitivePanel =
  document.getElementById(
    "encryptSensitivePanel"
  );

if (
  encryptSensitiveMetadata &&
  encryptSensitivePanel
) {
  encryptSensitiveMetadata.addEventListener(
    "change",
    () => {
      encryptSensitivePanel.classList.toggle(
        "hidden",
        !encryptSensitiveMetadata.checked
      );
    }
  );
}

/*
 * Office metadata extraction.
 * DOCX/XLSX/PPTX are ZIP packages containing XML properties.
 * Everything found in the core-properties XML is displayed.
 */
async function extractOfficeMetadata(file, add) {
  if (typeof JSZip === "undefined") {
    throw new Error("JSZip is not available.");
  }

  const zip = await JSZip.loadAsync(file);

  const propertyFiles = [
    "docProps/core.xml",
    "docProps/app.xml",
    "docProps/custom.xml"
  ];

  let found = false;

  for (const path of propertyFiles) {
    const entry = zip.file(path);

    if (!entry) continue;

    const xml = await entry.async("text");
    const document = new DOMParser().parseFromString(
      xml,
      "application/xml"
    );

    if (document.querySelector("parsererror")) {
      continue;
    }

    const elements = Array.from(document.documentElement.children);

    for (const element of elements) {
      const value = element.textContent?.trim();

      if (!value) continue;

      const namespace =
        element.namespaceURI || "unknown";

      const localName =
        element.localName || element.nodeName;

      add(
        `Office ${localName}`,
        value
      );

      found = true;
    }
  }

  return found;
}

/*
 * Audio/video metadata extraction.
 * MediaInfo.js runs locally in the browser through WebAssembly.
 * full: true requests all internal metadata fields.
 */
async function extractQuickTimeLocation(file, add) {
  const MAX_SCAN_BYTES = 4 * 1024 * 1024;
  const buffer = new Uint8Array(
    await file.slice(0, Math.min(file.size, MAX_SCAN_BYTES)).arrayBuffer()
  );

  const text = new TextDecoder("latin1").decode(buffer);

  const keys = [
    "com.apple.quicktime.location.ISO6709",
    "©xyz"
  ];

  for (const key of keys) {
    const index = text.indexOf(key);

    if (index === -1) continue;

    const start = index + key.length;
    const end = Math.min(start + 128, text.length);

    const value = text
      .slice(start, end)
      .replace(/[^\x20-\x7E+\-./]/g, "")
      .trim();

    const match = value.match(
      /[+-]\d{2,3}(?:\.\d+)?[+-]\d{2,3}(?:\.\d+)?(?:[+-]\d+(?:\.\d+)?)?\//
    );

    if (match) {
      add("GPS Location", match[0]);
      return true;
    }
  }

  return false;
}
async function extractMediaMetadata(file, add) {
  if (typeof MediaInfo === "undefined") {
    throw new Error("MediaInfo.js is not available.");
  }

  const mediaInfoFactory =
    MediaInfo.mediaInfoFactory ||
    MediaInfo.default ||
    MediaInfo;

  if (typeof mediaInfoFactory !== "function") {
    throw new Error("MediaInfo factory is not available.");
  }

  const mediaInfo = await mediaInfoFactory({
    format: "object",
    full: true,
    locateFile: () => "lib/MediaInfoModule.wasm"
  });

  const result = await mediaInfo.analyzeData(
    () => file.size,
    async (chunkSize, offset) => {
      const buffer = await file.slice(
        offset,
        offset + chunkSize
      ).arrayBuffer();

      return new Uint8Array(buffer);
    }
  );

  let found = false;

  const addTrack = (track, type) => {
    if (!track || typeof track !== "object") return;

    for (const [key, value] of Object.entries(track)) {
      if (
        value === undefined ||
        value === null ||
        value === ""
      ) {
        continue;
      }

      const displayValue =
        Array.isArray(value)
          ? value.join(", ")
          : typeof value === "object"
            ? JSON.stringify(value)
            : value;

      add(`${type} ${key}`, displayValue);
      found = true;
    }
  };

  if (result && Array.isArray(result.media?.track)) {
    for (const track of result.media.track) {
      const type =
        track["@type"] ||
        "Media";

      addTrack(track, type);
    }
  }

  if (typeof mediaInfo.close === "function") {
    mediaInfo.close();
  }

  return found;
}

/* Sensitive metadata auto-detection */
async function detectSensitiveMetadata(file) {
  const content =
    document.getElementById("sensitiveMetadataContent");

  if (!content || !file) return;

  content.innerHTML =
    "<p>Detecting metadata...</p>";

  const rows = [];

  const add = (label, value) => {
    if (
      value !== undefined &&
      value !== null &&
      String(value).trim() !== ""
    ) {
      const safeLabel =
        String(label)
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;");

      const safeValue =
        String(value)
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;");

      rows.push(
        `<div><span>${safeLabel}</span><strong>${safeValue}</strong></div>`
      );
    }
  };

  add("MIME type", file.type || "Unknown");

  const type =
    (file.type || "").toLowerCase();

  const name =
    file.name.toLowerCase();

  const isImage =
    type.startsWith("image/") ||
    /\.(jpg|jpeg|png|gif|webp|tif|tiff|heic|heif|avif|bmp|ico)$/i.test(name);

  let metadataFound = false;

  /*
   * Audio/video metadata extraction.
   * MediaInfo.js handles supported media formats locally.
   */
  const isMedia =
    type.startsWith("audio/") ||
    type.startsWith("video/") ||
    /\.(mp3|wav|flac|m4a|aac|ogg|opus|wma|mp4|m4v|mov|mkv|webm|avi|wmv|mpeg|mpg|3gp|3g2|ts|mts|m2ts)$/i.test(name);

  if (isMedia) {
    try {
      const mediaFound =
        await extractMediaMetadata(file, add);

      if (mediaFound) {
        metadataFound = true;
      }

      const locationFound =
        await extractQuickTimeLocation(file, add);

      if (locationFound) {
        metadataFound = true;
      }
    } catch (error) {
      console.error(
        "MediaInfo metadata error:",
        error
      );

      add(
        "Metadata parser",
        "Unable to read media metadata"
      );
    }
  }

  if (
    isImage &&
    typeof exifr !== "undefined"
  ) {
    try {
      const metadata =
        await exifr.parse(file, {
          tiff: true,
          exif: true,
          gps: true,
          iptc: true,
          icc: true,
          xmp: true,
          jfif: true,
          ihdr: true,
          translateValues: false
        });

      if (metadata && typeof metadata === "object") {
        console.log("RAW GPS:", {
          GPSLatitude: metadata.GPSLatitude,
          GPSLatitudeRef: metadata.GPSLatitudeRef,
          GPSLongitude: metadata.GPSLongitude,
          GPSLongitudeRef: metadata.GPSLongitudeRef,
          GPSAltitude: metadata.GPSAltitude,
          GPSAltitudeRef: metadata.GPSAltitudeRef
        });

        if (typeof EXIF !== "undefined") {
          EXIF.getData(file, function () {
            const lat = EXIF.getTag(this, "GPSLatitude");
            const latRef = EXIF.getTag(this, "GPSLatitudeRef");
            const lon = EXIF.getTag(this, "GPSLongitude");
            const lonRef = EXIF.getTag(this, "GPSLongitudeRef");
            const alt = EXIF.getTag(this, "GPSAltitude");

            const gpsNumber = (v) => {
              if (typeof v === "number") return v;
              if (v && typeof v === "object") {
                const n = Number(v.numerator);
                const d = Number(v.denominator);
                if (Number.isFinite(n) && Number.isFinite(d) && d)
                  return n / d;
              }
              return Number(v);
            };

            const gpsDms = (v) => {
              if (!v || !v.length) return NaN;
              const a = v.map(gpsNumber);
              if (!a.every(Number.isFinite)) return NaN;
              return a[0] + a[1] / 60 + a[2] / 3600;
            };

            const latitude = gpsDms(lat);
            const longitude = gpsDms(lon);
            const altitude = gpsNumber(alt);

            if (Number.isFinite(latitude) && Number.isFinite(longitude)) {
              add(
                "GPS Latitude",
                String(latRef).toUpperCase() === "S" ? -latitude : latitude
              );
              add(
                "GPS Longitude",
                String(lonRef).toUpperCase() === "W" ? -longitude : longitude
              );
              if (Number.isFinite(altitude)) {
                add("GPS Altitude", altitude);
              }
              metadataFound = true;
            }
          });
        }

        if (typeof ExifReader !== "undefined") {
          try {
            const tags = await ExifReader.load(file, {
              expanded: true
            });

            const gps = tags.gps || {};
            const latitude = Number(gps.Latitude);
            const longitude = Number(gps.Longitude);
            const altitude = Number(gps.Altitude);

            if (
              Number.isFinite(latitude) &&
              Number.isFinite(longitude)
            ) {
              add("GPS Latitude", latitude);
              add("GPS Longitude", longitude);

              if (Number.isFinite(altitude)) {
                add("GPS Altitude", altitude);
              }

              metadataFound = true;
            }
          } catch (gpsError) {
            console.error("ExifReader GPS error:", gpsError);
          }
        }

        const gpsLatitude = metadata.GPSLatitude;
        const gpsLongitude = metadata.GPSLongitude;
        const gpsLatitudeRef = metadata.GPSLatitudeRef;
        const gpsLongitudeRef = metadata.GPSLongitudeRef;
        const gpsAltitude = metadata.GPSAltitude;

        const toNumber = (value) => {
          if (typeof value === "number") return value;

          const rational = (v) => {
            if (v && typeof v === "object") {
              const n = Number(v.numerator ?? v.num ?? v.value);
              const d = Number(v.denominator ?? v.den ?? 1);
              if (Number.isFinite(n) && Number.isFinite(d) && d !== 0)
                return n / d;
            }
            return Number(v);
          };

          if (Array.isArray(value)) {
            const nums = value.map(rational);
            if (nums.every(Number.isFinite)) {
              if (nums.length >= 3)
                return nums[0] + nums[1] / 60 + nums[2] / 3600;
              if (nums.length === 1) return nums[0];
            }
          }

          return rational(value);
        };

        const latitude = toNumber(gpsLatitude);
        const longitude = toNumber(gpsLongitude);
        const altitude = toNumber(gpsAltitude);

        if (Number.isFinite(latitude) && Number.isFinite(longitude)) {
          const finalLatitude =
            String(gpsLatitudeRef).toUpperCase() === "S"
              ? -Math.abs(latitude)
              : Math.abs(latitude);

          const finalLongitude =
            String(gpsLongitudeRef).toUpperCase() === "W"
              ? -Math.abs(longitude)
              : Math.abs(longitude);

          add("GPS Latitude", finalLatitude);
          add("GPS Longitude", finalLongitude);

          if (Number.isFinite(altitude)) {
            add("GPS Altitude", altitude);
          }

          metadataFound = true;
        }
      }

      if (
        metadata &&
        typeof metadata === "object"
      ) {
        for (
          const [key, value]
          of Object.entries(metadata)
        ) {
          if (
            value === undefined ||
            value === null ||
            value === ""
          ) {
            continue;
          }

          if (
            Array.isArray(value)
          ) {
            add(
              key,
              value.join(", ")
            );
          } else if (
            typeof value === "object"
          ) {
            add(
              key,
              JSON.stringify(value)
            );
          } else {
            add(key, value);
          }

          metadataFound = true;
        }
      }
    } catch (error) {
      console.error(
        "exifr metadata error:",
        error
      );

      add(
        "Metadata parser",
        "Unable to read all image metadata"
      );
    }
  }

  /*
   * PDF metadata extraction.
   * Parsed locally with pdf-lib; the file is never uploaded.
   */
  const isPDF =
    type === "application/pdf" ||
    name.endsWith(".pdf");

  if (
    isPDF &&
    typeof PDFLib !== "undefined"
  ) {
    try {
      const pdfBytes =
        await file.arrayBuffer();

      const pdfDoc =
        await PDFLib.PDFDocument.load(
          pdfBytes,
          {
            updateMetadata: false
          }
        );

      const pdfMetadata = [
        ["PDF Title", pdfDoc.getTitle()],
        ["PDF Author", pdfDoc.getAuthor()],
        ["PDF Subject", pdfDoc.getSubject()],
        ["PDF Keywords", pdfDoc.getKeywords()],
        ["PDF Creator", pdfDoc.getCreator()],
        ["PDF Producer", pdfDoc.getProducer()],
        ["PDF Creation Date", pdfDoc.getCreationDate()],
        ["PDF Modification Date", pdfDoc.getModificationDate()]
      ];

      for (const [label, value] of pdfMetadata) {
        if (value !== undefined && value !== null) {
          add(
            label,
            value instanceof Date
              ? value.toLocaleString()
              : value
          );
          metadataFound = true;
        }
      }
    } catch (error) {
      console.error(
        "PDF metadata error:",
        error
      );

      add(
        "Metadata parser",
        "Unable to read PDF metadata"
      );
    }
  }

  /*
   * Office metadata extraction.
   */
  const isOffice =
    /\.(docx|xlsx|pptx)$/i.test(name);

  if (isOffice) {
    try {
      const officeFound =
        await extractOfficeMetadata(file, add);

      if (officeFound) {
        metadataFound = true;
      }
    } catch (error) {
      console.error(
        "Office metadata error:",
        error
      );

      add(
        "Metadata parser",
        "Unable to read Office metadata"
      );
    }
  }

  /*
   * Basic format detection for non-images.
   * We intentionally do not claim that these
   * formats have been completely parsed.
   */
  if (!isImage) {
    const buffer =
      new Uint8Array(
        await file.arrayBuffer()
      );

    let detected = "Unknown";

    const startsWith = bytes =>
      bytes.every(
        (value, index) =>
          buffer[index] === value
      );

    if (
      startsWith([
        0x50, 0x4B, 0x03, 0x04
      ])
    ) {
      detected = "ZIP";
    } else if (
      startsWith([
        0x49, 0x44, 0x33
      ])
    ) {
      detected = "MP3";
    } else if (
      buffer.length >= 2 &&
      buffer[0] === 0xFF &&
      (buffer[1] & 0xE0) === 0xE0
    ) {
      detected = "MPEG Audio";
    } else if (
      startsWith([
        0x52, 0x49, 0x46, 0x46
      ]) &&
      buffer.length >= 12 &&
      String.fromCharCode(
        ...buffer.slice(8, 12)
      ) === "WAVE"
    ) {
      detected = "WAV";
    } else if (
      startsWith([
        0x4F, 0x67, 0x67, 0x53
      ])
    ) {
      detected = "OGG";
    } else if (
      startsWith([
        0x66, 0x4C, 0x61, 0x43
      ])
    ) {
      detected = "FLAC";
    } else if (
      startsWith([
        0x1A, 0x45, 0xDF, 0xA3
      ])
    ) {
      detected = "Matroska/WebM";
    } else if (
      startsWith([
        0x25, 0x50, 0x44, 0x46
      ])
    ) {
      detected = "PDF";
    } else if (
      startsWith([
        0x1F, 0x8B
      ])
    ) {
      detected = "GZIP";
    } else if (
      buffer.length >= 12 &&
      String.fromCharCode(
        ...buffer.slice(4, 8)
      ) === "ftyp"
    ) {
      detected = "ISO Base Media";
    }

    add(
      "Detected format",
      detected
    );
  }

  if (!metadataFound && rows.length === 4) {
    add(
      "Metadata",
      "No readable embedded metadata detected"
    );
  }

  const metadataRows = rows.join("");
  const previewRows = rows.slice(0, 6).join("");

  content.innerHTML = `<div class="sensitive-metadata-preview">${previewRows}<div class="metadata-preview-fade"></div><button type="button" class="view-all-metadata" id="viewAllMetadata">View all</button></div>`;

  const viewAllMetadata = document.getElementById("viewAllMetadata");

  if (viewAllMetadata) {
    viewAllMetadata.addEventListener("click", () => {
      const modal = document.getElementById("metadataModal");
      const allContent = document.getElementById("allMetadataContent");

      if (modal && allContent) {
        allContent.innerHTML = metadataRows;
        modal.classList.remove("hidden");
      }
    });
  }

  const closeMetadataModal =
    document.getElementById("closeMetadataModal");

  if (closeMetadataModal) {
    closeMetadataModal.onclick = () => {
      document
        .getElementById("metadataModal")
        ?.classList.add("hidden");
    };
  }

  const copyAllMetadata =
    document.getElementById("copyAllMetadata");

  if (copyAllMetadata) {
    copyAllMetadata.onclick = async () => {
      const allContent =
        document.getElementById("allMetadataContent");

      if (!allContent) return;

      const text =
        Array.from(allContent.querySelectorAll(":scope > div"))
          .map(row => {
            const label =
              row.querySelector("span")?.textContent || "";
            const value =
              row.querySelector("strong")?.textContent || "";

            return `${label}: ${value}`;
          })
          .join("\n");

      await navigator.clipboard.writeText(text);

      copyAllMetadata.textContent = "Copied";

      setTimeout(() => {
        copyAllMetadata.textContent = "Copy";
      }, 1200);
    };
  }
}

if (
  encryptSensitiveMetadata &&
  encryptSensitivePanel
) {
  encryptSensitiveMetadata.addEventListener(
    "change",
    async () => {
      if (
        encryptSensitiveMetadata.checked
      ) {
        const file =
          encryptFile?.files?.[0];

        if (file) {
          await detectSensitiveMetadata(
            file
          );
        }
      }
    }
  );
}


if (encryptExtension && customExtension) {
  encryptExtension.addEventListener("change", () => {
    customExtension.classList.toggle(
      "hidden",
      encryptExtension.value !== "custom"
    );

    if (encryptExtension.value !== "custom") {
      customExtension.value = "";
    }
  });
}
