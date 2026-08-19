const fileInput = document.getElementById("fileInput");
const passwordInput = document.getElementById("passwordInput");
const encryptButton = document.getElementById("encryptButton");
const decryptButton = document.getElementById("decryptButton");
const status = document.getElementById("status");

const MAGIC = new TextEncoder().encode("SFC1");
const SALT_SIZE = 16;
const IV_SIZE = 12;
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

function downloadFile(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = url;
  link.download = filename;
  link.click();

  URL.revokeObjectURL(url);
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

    status.textContent = "Encrypting...";

    const data = await file.arrayBuffer();

    const salt = crypto.getRandomValues(new Uint8Array(SALT_SIZE));
    const iv = crypto.getRandomValues(new Uint8Array(IV_SIZE));

    const key = await deriveKey(password, salt);

    const encrypted = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv
      },
      key,
      data
    );

    const originalName = new TextEncoder().encode(file.name);
    const nameLength = new Uint32Array([originalName.length]);

    const output = new Blob([
      MAGIC,
      salt,
      iv,
      new Uint8Array(nameLength.buffer),
      originalName,
      new Uint8Array(encrypted)
    ], {
      type: "application/octet-stream"
    });

    const encryptedName = file.name.includes(".")
      ? file.name.substring(0, file.name.lastIndexOf("."))
      : file.name;

    downloadFile(output, encryptedName);

    status.textContent = "File encrypted successfully.";
  } catch (error) {
    console.error(error);
    status.textContent = "Encryption failed.";
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

    status.textContent = "Decrypting...";

    const data = new Uint8Array(await file.arrayBuffer());

    let offset = 0;

    const magic = data.slice(offset, offset + 4);
    offset += 4;

    if (new TextDecoder().decode(magic) !== "SFC1") {
      throw new Error("Invalid SecureFileCrypt file.");
    }

    const salt = data.slice(offset, offset + SALT_SIZE);
    offset += SALT_SIZE;

    const iv = data.slice(offset, offset + IV_SIZE);
    offset += IV_SIZE;

    const nameLength = new DataView(
      data.buffer,
      data.byteOffset + offset,
      4
    ).getUint32(0, true);

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
      new Blob([decrypted], { type: "application/octet-stream" }),
      originalName
    );

    status.textContent = "File decrypted successfully.";
  } catch (error) {
    console.error(error);
    status.textContent = "Decryption failed: wrong password or invalid file.";
  }
});
