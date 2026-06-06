/**
 * Cryptographic Utilities for VaultCore
 * Uses native Web Crypto API (SubtleCrypto)
 */

const CryptoUtils = {
    // Generate a random salt/IV
    generateRandomBytes(length) {
        return crypto.getRandomValues(new Uint8Array(length));
    },

    // Derive an AES-GCM key from a password using PBKDF2
    async deriveKey(password, salt) {
        const enc = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            "raw",
            enc.encode(password),
            { name: "PBKDF2" },
            false,
            ["deriveBits", "deriveKey"]
        );

        return await crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: 100000,
                hash: "SHA-256"
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
    },

    // Encrypt a string using a key
    async encryptData(key, text) {
        const iv = this.generateRandomBytes(12);
        const enc = new TextEncoder();
        
        const cipherBuffer = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            key,
            enc.encode(text)
        );

        // We return the IV and cipher text as base64 so it can be stored
        return {
            iv: this.bufferToBase64(iv),
            cipherText: this.bufferToBase64(cipherBuffer)
        };
    },

    // Decrypt data using a key
    async decryptData(key, encryptedObj) {
        try {
            const iv = this.base64ToBuffer(encryptedObj.iv);
            const cipherBuffer = this.base64ToBuffer(encryptedObj.cipherText);

            const decBuffer = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: iv },
                key,
                cipherBuffer
            );

            const dec = new TextDecoder();
            return dec.decode(decBuffer);
        } catch (e) {
            throw new Error("Invalid master password or corrupted data.");
        }
    },

    // Generate a secure random password (e.g. for new entries)
    generatePassword(length = 16) {
        const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~`|}{[]:;?><,./-=";
        let password = "";
        const randomValues = new Uint32Array(length);
        crypto.getRandomValues(randomValues);
        for (let i = 0; i < length; i++) {
            password += chars[randomValues[i] % chars.length];
        }
        return password;
    },

    // Get SHA-1 hash for HaveIBeenPwned API (returns hex string)
    async sha1Hash(text) {
        const enc = new TextEncoder();
        const hashBuffer = await crypto.subtle.digest('SHA-1', enc.encode(text));
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        return hashHex.toUpperCase();
    },

    // Helper: Buffer to Base64
    bufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    },

    // Helper: Base64 to Buffer
    base64ToBuffer(base64) {
        const binary_string = window.atob(base64);
        const len = binary_string.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binary_string.charCodeAt(i);
        }
        return bytes.buffer;
    }
};

window.CryptoUtils = CryptoUtils;
