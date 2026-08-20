importScripts("fflate.min.js");

self.onmessage = (event) => {
  try {
    const { encrypted, password } = event.data;

    const files = {
      "encrypted-file.sfc": new Uint8Array(encrypted),
      "password.txt": new TextEncoder().encode(
        "SecureFileCrypt Password\n\n" +
        password +
        "\n\nKEEP THIS ZIP PRIVATE.\n" +
        "Anyone with this ZIP can decrypt the encrypted file."
      )
    };

    const zipData = fflate.zipSync(files);

    self.postMessage(
      { zip: zipData.buffer },
      [zipData.buffer]
    );
  } catch (error) {
    self.postMessage({
      error: error?.message || String(error)
    });
  }
};
