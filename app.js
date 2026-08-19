const encryptFile = document.getElementById("encryptFile");
const decryptFile = document.getElementById("decryptFile");

const encryptPassword = document.getElementById("encryptPassword");
const decryptPassword = document.getElementById("decryptPassword");

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
const decryptDownload = document.getElementById("decryptDownload");

const encryptTab = document.getElementById("encryptTab");
const decryptTab = document.getElementById("decryptTab");

const encryptPage = document.getElementById("encryptPage");
const decryptPage = document.getElementById("decryptPage");

const warningModal = document.getElementById("warningModal");
const closeWarning = document.getElementById("closeWarning");

const OLD_MAGIC = "SFC1";
const OLD_CHUNK_MAGIC = "SFC2";
const MAGIC = new TextEncoder().encode("SFC3");

const SALT_SIZE = 16;
const IV_SIZE = 12;
const CHUNK_SIZE = 4 * 1024 * 1024;

const ARGON2_TIME = 3;
const ARGON2_MEMORY = 65536;
const ARGON2_PARALLELISM = 1;
const ARGON2_HASH_LENGTH = 32;

let pendingEncryptDownload = null;
let pendingDecryptDownload = null;

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
  return Number(
    new DataView(
      data.buffer,
      data.byteOffset + offset,
      8
    ).getBigUint64(0, true)
  );
}

function prepareDownload(blob, filename) {
  return {
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

function downloadPending(download) {
  if (!download) return;

  const link = document.createElement("a");

  link.href = download.url;
  link.download = download.filename;

  document.body.appendChild(link);
  link.click();
  link.remove();

  setTimeout(() => {
    URL.revokeObjectURL(download.url);
  }, 60000);
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

      const header = [
        MAGIC,
        salt,
        baseIv,
        writeUint32(
          originalName.length
        ),
        writeUint32(CHUNK_SIZE),
        writeUint64(file.size),
        originalName
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

      const encryptedName =
        file.name.includes(".")
          ? file.name.substring(
              0,
              file.name.lastIndexOf(".")
            )
          : file.name;

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

      warningModal.classList.remove(
        "hidden"
      );
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

encryptDownload.addEventListener(
  "click",
  () => {
    downloadPending(
      pendingEncryptDownload
    );
  }
);

decryptDownload.addEventListener(
  "click",
  () => {
    downloadPending(
      pendingDecryptDownload
    );
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

document
  .querySelectorAll(
    ".toggle-password"
  )
  .forEach(button => {
    button.addEventListener(
      "click",
      () => {
        const input =
          document.getElementById(
            button.dataset.target
          );

        if (
          input.type === "password"
        ) {
          input.type = "text";
          button.textContent =
            "Hide";
        } else {
          input.type = "password";
          button.textContent =
            "Show";
        }
      }
    );
  });

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
