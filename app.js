const fileInput = document.getElementById("fileInput");
const passwordInput = document.getElementById("passwordInput");
const encryptButton = document.getElementById("encryptButton");
const decryptButton = document.getElementById("decryptButton");
const status = document.getElementById("status");

const OLD_MAGIC = "SFC1";
const MAGIC = new TextEncoder().encode("SFC2");

const SALT_SIZE = 16;
const IV_SIZE = 12;
const CHUNK_SIZE = 4 * 1024 * 1024; // 4 MiB
const KEY_ITERATIONS = 600000;

async function deriveKey(password, salt) {
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
      iterations: KEY_ITERATIONS,
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
  const iv = new Uint8Array(baseIv);
  const view = new DataView(iv.buffer);

  view.setUint32(8, counter, false);

  return iv;
}

function downloadFile(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();

  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function writeUint32(value) {
  const buffer = new ArrayBuffer(4);
  new DataView(buffer).setUint32(0, value, true);
  return new Uint8Array(buffer);
}

function writeUint64(value) {
  const buffer = new ArrayBuffer(8);
  new DataView(buffer).setBigUint64(0, BigInt(value), true);
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
  return Number(
    new DataView(
      data.buffer,
      data.byteOffset + offset,
      8
    ).getBigUint64(0, true)
  );
}

async function decryptOldSFC1(data, password) {
  let offset = 0;

  const magic = new TextDecoder().decode(data.slice(offset, offset + 4));
  offset += 4;

  if (magic !== OLD_MAGIC) {
    throw new Error("Invalid SecureFileCrypt file.");
  }

  const salt = data.slice(offset, offset + SALT_SIZE);
  offset += SALT_SIZE;

  const iv = data.slice(offset, offset + IV_SIZE);
  offset += IV_SIZE;

  const nameLength = readUint32(data, offset);
  offset += 4;

  const originalName = new TextDecoder().decode(
    data.slice(offset, offset + nameLength)
  );

  offset += nameLength;

  const encrypted = data.slice(offset);

  const key = await deriveKey(password, salt);

  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv
    },
    key,
    encrypted
  );

  downloadFile(
    new Blob([decrypted], {
      type: "application/octet-stream"
    }),
    originalName
  );
}

encryptButton.addEventListener("click", async () => {
  try {
    const file = fileInput.files[0];
    const password = passwordInput.value;

    if (!file) {
      status.textContent = "Select a file first.";
      return;
    }

    if (!password) {
      status.textContent = "Enter a password.";
      return;
    }

    encryptButton.disabled = true;
    decryptButton.disabled = true;

    status.textContent = "Preparing encryption...";

    const salt = crypto.getRandomValues(
      new Uint8Array(SALT_SIZE)
    );

    const baseIv = crypto.getRandomValues(
      new Uint8Array(IV_SIZE)
    );

    const key = await deriveKey(password, salt);

    const originalName = new TextEncoder().encode(file.name);

    if (originalName.length > 0xffffffff) {
      throw new Error("Filename is too long.");
    }

    const header = [
      MAGIC,
      salt,
      baseIv,
      writeUint32(originalName.length),
      writeUint32(CHUNK_SIZE),
      writeUint64(file.size),
      originalName
    ];

    const encryptedChunks = [];
    const chunkCount = Math.ceil(file.size / CHUNK_SIZE);

    for (let index = 0; index < chunkCount; index++) {
      const start = index * CHUNK_SIZE;
      const end = Math.min(start + CHUNK_SIZE, file.size);

      const chunk = await file.slice(start, end).arrayBuffer();

      const iv = createChunkIv(baseIv, index);

      const encrypted = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv
        },
        key,
        chunk
      );

      encryptedChunks.push(new Uint8Array(encrypted));

      const percent = Math.round(
        ((index + 1) / chunkCount) * 100
      );

      status.textContent = `Encrypting... ${percent}%`;

      await new Promise(resolve => setTimeout(resolve, 0));
    }

    const output = new Blob(
      [...header, ...encryptedChunks],
      {
        type: "application/octet-stream"
      }
    );

    const encryptedName = file.name.includes(".")
      ? file.name.substring(0, file.name.lastIndexOf("."))
      : file.name;

    downloadFile(output, encryptedName);

    status.textContent = "File encrypted successfully.";
  } catch (error) {
    console.error(error);
    status.textContent = "Encryption failed.";
  } finally {
    encryptButton.disabled = false;
    decryptButton.disabled = false;
  }
});

decryptButton.addEventListener("click", async () => {
  try {
    const file = fileInput.files[0];
    const password = passwordInput.value;

    if (!file) {
      status.textContent = "Select an encrypted file first.";
      return;
    }

    if (!password) {
      status.textContent = "Enter the password.";
      return;
    }

    decryptButton.disabled = true;
    encryptButton.disabled = true;

    const data = new Uint8Array(await file.arrayBuffer());

    const magic = new TextDecoder().decode(
      data.slice(0, 4)
    );

    if (magic === OLD_MAGIC) {
      status.textContent = "Decrypting old format...";
      await decryptOldSFC1(data, password);
      status.textContent = "File decrypted successfully.";
      return;
    }

    if (magic !== "SFC2") {
      throw new Error("Invalid SecureFileCrypt file.");
    }

    let offset = 4;

    const salt = data.slice(offset, offset + SALT_SIZE);
    offset += SALT_SIZE;

    const baseIv = data.slice(offset, offset + IV_SIZE);
    offset += IV_SIZE;

    const nameLength = readUint32(data, offset);
    offset += 4;

    const chunkSize = readUint32(data, offset);
    offset += 4;

    const originalSize = readUint64(data, offset);
    offset += 8;

    if (
      chunkSize === 0 ||
      chunkSize > 64 * 1024 * 1024
    ) {
      throw new Error("Invalid chunk size.");
    }

    const originalName = new TextDecoder().decode(
      data.slice(offset, offset + nameLength)
    );

    offset += nameLength;

    const key = await deriveKey(password, salt);

    const chunkCount = Math.ceil(
      originalSize / chunkSize
    );

    const decryptedChunks = [];

    for (let index = 0; index < chunkCount; index++) {
      const plaintextSize =
        index === chunkCount - 1
          ? originalSize - index * chunkSize
          : chunkSize;

      const encryptedSize = plaintextSize + 16;

      if (offset + encryptedSize > data.length) {
        throw new Error("Encrypted file is incomplete.");
      }

      const encrypted = data.slice(
        offset,
        offset + encryptedSize
      );

      offset += encryptedSize;

      const iv = createChunkIv(baseIv, index);

      const decrypted = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv
        },
        key,
        encrypted
      );

      decryptedChunks.push(new Uint8Array(decrypted));

      const percent = Math.round(
        ((index + 1) / chunkCount) * 100
      );

      status.textContent = `Decrypting... ${percent}%`;

      await new Promise(resolve => setTimeout(resolve, 0));
    }

    if (offset !== data.length) {
      throw new Error("Invalid encrypted file.");
    }

    downloadFile(
      new Blob(decryptedChunks, {
        type: "application/octet-stream"
      }),
      originalName
    );

    status.textContent = "File decrypted successfully.";
  } catch (error) {
    console.error(error);
    status.textContent =
      "Decryption failed: wrong password or invalid file.";
  } finally {
    encryptButton.disabled = false;
    decryptButton.disabled = false;
  }
});
