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
const decryptButton = document.getElementById("decryptButton");

const encryptStatus = document.getElementById("encryptStatus");
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
    showFileMetadata(
      encryptFile.files[0],
      "encrypt"
    );
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

  add("Filename", file.name);
  add("MIME type", file.type || "Unknown");
  add("Size", formatBytes(file.size));
  add(
    "Last modified",
    new Date(file.lastModified).toLocaleString()
  );

  const type =
    (file.type || "").toLowerCase();

  const name =
    file.name.toLowerCase();

  const isImage =
    type.startsWith("image/") ||
    /\.(jpg|jpeg|png|gif|webp|tif|tiff|heic|heif|avif|bmp|ico)$/i.test(name);

  let metadataFound = false;

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

  content.innerHTML =
    rows.join("");
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
