async function getKeyFromPassword(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: 100000,
        hash: "SHA-256"
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }
  
  async function encryptFile() {
    const fileInput = document.getElementById('fileInput');
    const password = document.getElementById('password').value;
  
    if (!fileInput.files.length || !password) {
      alert('Please select a file and enter a password.');
      return;
    }
  
    const file = fileInput.files[0];
    const arrayBuffer = await file.arrayBuffer();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await getKeyFromPassword(password, salt);
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      key,
      arrayBuffer
    );
  
    const encoder = new TextEncoder();
    const filenameBytes = encoder.encode(file.name);
    const filenameLength = new Uint8Array([filenameBytes.length]);
  
    const combined = new Uint8Array(
      salt.byteLength + iv.byteLength + 1 + filenameBytes.byteLength + encrypted.byteLength
    );
    let offset = 0;
    combined.set(salt, offset); offset += salt.byteLength;
    combined.set(iv, offset); offset += iv.byteLength;
    combined.set(filenameLength, offset); offset += 1;
    combined.set(filenameBytes, offset); offset += filenameBytes.length;
    combined.set(new Uint8Array(encrypted), offset);
  
    const blob = new Blob([combined], { type: "application/octet-stream" });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = file.name + ".enc";
    a.click();
  }
  
  async function decryptFile() {
    const decryptInput = document.getElementById('decryptInput');
    const password = document.getElementById('decryptPassword').value;
  
    if (!decryptInput.files.length || !password) {
      alert('Please select an encrypted file and enter the password.');
      return;
    }
  
    const file = decryptInput.files[0];
    const encryptedData = new Uint8Array(await file.arrayBuffer());
  
    const salt = encryptedData.slice(0, 16);
    const iv = encryptedData.slice(16, 28);
    const filenameLength = encryptedData[28];
    const filenameBytes = encryptedData.slice(29, 29 + filenameLength);
    const encryptedContent = encryptedData.slice(29 + filenameLength);
  
    const decoder = new TextDecoder();
    const originalFilename = decoder.decode(filenameBytes);
  
    try {
      const key = await getKeyFromPassword(password, salt);
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encryptedContent
      );
  
      const blob = new Blob([decrypted]);
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = originalFilename;
      a.click();
    } catch (e) {
      alert("❌ Decryption failed. Incorrect password or corrupted file.");
    }
  }
  