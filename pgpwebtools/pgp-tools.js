// pgp-tools.js

// Assume openpgp.js is loaded globally (e.g., via CDN in the HTML)
// if (typeof openpgp === 'undefined') {
//     console.error("FATAL: openpgp.js is not loaded. PGP Tools cannot operate.");
// }

const PGP_TOOLS_CONFIG = {
    CURVE: 'curve25519',
    USER_ID_PLACEHOLDER_NAME: 'PGP Tools User',
    LS_PUBLIC_KEY_SUFFIX: '.pub',
    LS_PRIVATE_KEY_SUFFIX: '.priv',
};

const DecryptedPrivateKeyCache = new Map();

// --- Logging ---
function logPgpTool(message, type = 'info', keyname = null) {
    const prefix = keyname ? `[PGP-TOOLS][${keyname}]` : '[PGP-TOOLS]';
    console.log(`${prefix} [${type.toUpperCase()}] ${message}`);
    // In a real web app, you might append to a log div on the page as well
    // For simplicity, this module will just console.log
}

// --- Helper to construct localStorage keys ---
function getPublicKeyLsKey(keyname) {
    return `${keyname}${PGP_TOOLS_CONFIG.LS_PUBLIC_KEY_SUFFIX}`;
}

function getPrivateKeyLsKey(keyname) {
    return `${keyname}${PGP_TOOLS_CONFIG.LS_PRIVATE_KEY_SUFFIX}`;
}

// --- Helper function to trigger a browser download ---
function triggerDownload(filename, textContent) {
    try {
        const element = document.createElement('a');
        const file = new Blob([textContent], { type: 'text/plain;charset=utf-8' });
        element.href = URL.createObjectURL(file);
        element.download = filename;
        document.body.appendChild(element); // Required for Firefox
        element.click();
        document.body.removeChild(element);
        URL.revokeObjectURL(element.href);
        logPgpTool(`Download initiated for ${filename}.`, 'info');
    } catch (e) {
        logPgpTool(`Error triggering download for ${filename}: ${e.message}`, 'error');
        // Consider providing user feedback here if automatic download fails.
        // For example, by updating a status message on the page.
        alert(`Could not automatically start download for ${filename}. Please use manual download links if available, or check the browser console.`);
    }
}


// --- Core PGP Functions ---

/**
 * Generates a new PGP key pair, encrypts the private key with the password,
 * stores both in localStorage under the given keyname, and triggers downloads.
 * @param {string} keyname - The name to associate with this key pair (used for storage).
 * @param {string} password - The password to encrypt the private key.
 * @param {string} [email] - Optional email for the PGP User ID.
 * @returns {Promise<{publicKeyArmored: string, privateKeyObject: openpgp.PrivateKey}|null>}
 */
async function generateKeys(keyname, password, email = null) {
    logPgpTool(`Generating new keys for '${keyname}'...`, 'info', keyname);
    if (!keyname || !password) {
        logPgpTool('Keyname and password are required for generateKeys.', 'error', keyname);
        return null;
    }

    try {
        const userEmail = email || `${keyname.toLowerCase().replace(/\s+/g, '.')}@pgptools.local`;
        const keyOptions = {
            type: 'ecc',
            curve: PGP_TOOLS_CONFIG.CURVE,
            userIDs: [{ name: keyname, email: userEmail }],
        };

        logPgpTool('Calling openpgp.generateKey (expecting armored strings by default for this version)...', 'debug', keyname);
        const generatedOutput = await openpgp.generateKey(keyOptions);

        if (!generatedOutput || typeof generatedOutput.privateKey !== 'string' || typeof generatedOutput.publicKey !== 'string') {
            throw new Error('openpgp.generateKey did not return armored key strings as expected.');
        }

        const unencryptedPrivateKeyArmored = generatedOutput.privateKey;
        const publicKeyArmored = generatedOutput.publicKey;

        logPgpTool('Parsing unencrypted armored private key string into an object...', 'debug', keyname);
        const privateKeyObjectForEncryption = await openpgp.readPrivateKey({
            armoredKey: unencryptedPrivateKeyArmored
        });
        logPgpTool('Parsed private key object successfully.', 'debug', keyname);

        logPgpTool('Encrypting the private key object...', 'debug', keyname);
        const encryptedPrivateKeyResult = await openpgp.encryptKey({
            privateKey: privateKeyObjectForEncryption,
            passphrase: password
        });
        logPgpTool('encryptKey call completed.', 'debug', keyname);

        let finalEncryptedArmoredPrivateKey;
        if (typeof encryptedPrivateKeyResult === 'string') {
            finalEncryptedArmoredPrivateKey = encryptedPrivateKeyResult;
            logPgpTool('encryptKey returned an armored string directly.', 'debug', keyname);
        } else if (encryptedPrivateKeyResult && typeof encryptedPrivateKeyResult.armor === 'function') {
            finalEncryptedArmoredPrivateKey = await encryptedPrivateKeyResult.armor();
            logPgpTool('encryptKey returned an object, armored it separately.', 'debug', keyname);
        } else {
            throw new Error('openpgp.encryptKey did not return an armored string or an armor-able key object.');
        }

        localStorage.setItem(getPublicKeyLsKey(keyname), publicKeyArmored);
        localStorage.setItem(getPrivateKeyLsKey(keyname), finalEncryptedArmoredPrivateKey);

        DecryptedPrivateKeyCache.set(keyname, privateKeyObjectForEncryption);

        logPgpTool(`Keys generated and saved for '${keyname}'. Private key encrypted.`, 'success', keyname);

        // --- Trigger Automatic Downloads ---
        try {
            logPgpTool(`Attempting to trigger download for public key: ${keyname}.pub.asc`, 'debug', keyname);
            triggerDownload(`${keyname}.pub.asc`, publicKeyArmored);

            logPgpTool(`Attempting to trigger download for encrypted private key: ${keyname}.priv.asc`, 'debug', keyname);
            triggerDownload(`${keyname}.priv.asc`, finalEncryptedArmoredPrivateKey);
            logPgpTool('Backup download prompts initiated. User should save these files securely and remember their password.', 'info', keyname);
        } catch (downloadError) {
            logPgpTool(`Automatic download initiation failed: ${downloadError.message}. User may need to use manual download links if provided.`, 'warn', keyname);
        }
        // --- End Automatic Downloads ---

        return {
            publicKeyArmored: publicKeyArmored,
            privateKeyObject: privateKeyObjectForEncryption
        };
    } catch (error) {
        logPgpTool(`Error generating keys for '${keyname}': ${error.message}`, 'error', keyname);
        console.error(error); // Keep original error for dev console
        return null;
    }
}

/**
 * Loads PGP keys from localStorage for a given keyname and decrypts the private key.
 * @param {string} keyname - The name of the key pair to load.
 * @param {string} password - The password to decrypt the private key.
 * @returns {Promise<{publicKeyArmored: string, privateKeyObject: openpgp.PrivateKey}|null>}
 */
async function loadKeys(keyname, password) {
    logPgpTool(`Attempting to load keys for '${keyname}' (v6.1.1 - using openpgp.decryptKey)...`, 'info', keyname);
    if (!keyname || !password) {
        logPgpTool('Keyname and password are required for loadKeys.', 'error', keyname);
        return null;
    }

    const publicKeyArmored = localStorage.getItem(getPublicKeyLsKey(keyname));
    const privateKeyArmoredEncrypted = localStorage.getItem(getPrivateKeyLsKey(keyname));

    if (!publicKeyArmored || !privateKeyArmoredEncrypted) {
        logPgpTool(`No keys found in localStorage for '${keyname}'.`, 'warn', keyname);
        return null;
    }

    try {
        logPgpTool('Calling openpgp.decryptKey with (parsed) armoredKey AND passphrase...', 'debug', keyname);
        const decryptedPrivateKeyObject = await openpgp.decryptKey({
            privateKey: await openpgp.readKey({ armoredKey: privateKeyArmoredEncrypted }),
            passphrase: password
        });

        if (!decryptedPrivateKeyObject) {
            throw new Error("openpgp.decryptKey returned null or undefined.");
        }
        if (!(await decryptedPrivateKeyObject.isDecrypted())) {
            throw new Error("Private key not decrypted after openpgp.decryptKey, though no error was thrown (password might be incorrect or key issue).");
        }
        
        DecryptedPrivateKeyCache.set(keyname, decryptedPrivateKeyObject);

        logPgpTool(`Keys loaded and private key object is ready for '${keyname}' (decrypted by openpgp.decryptKey).`, 'success', keyname);
        return {
            publicKeyArmored: publicKeyArmored,
            privateKeyObject: decryptedPrivateKeyObject
        };
    } catch (error) {
        logPgpTool(`Failed to load/decrypt keys for '${keyname}': ${error.message}`, 'error', keyname);
        console.error(error);
        DecryptedPrivateKeyCache.delete(keyname);
        return null;
    }
}

/**
 * Checks if a given key pair (identified by keyname) is "ready".
 * @param {string} keyname - The name of the key pair.
 * @returns {boolean} True if keys are present and private key is decrypted in cache.
 */
function isPgpReady(keyname) {
    if (!keyname) return false;
    const pubKeyExists = !!localStorage.getItem(getPublicKeyLsKey(keyname));
    const privKeyExists = !!localStorage.getItem(getPrivateKeyLsKey(keyname));
    const privKeyDecrypted = DecryptedPrivateKeyCache.has(keyname);
    const ready = pubKeyExists && privKeyExists && privKeyDecrypted;
    logPgpTool(`isPgpReady check for '${keyname}': Ready=${ready}`, 'debug', keyname);
    return ready;
}

/**
 * Retrieves the decrypted private key object for a given keyname from cache.
 * @param {string} keyname - The name of the key pair.
 * @returns {openpgp.PrivateKey|null} The decrypted private key object or null.
 */
function getDecryptedPrivateKeyObject(keyname) { // Changed from async as it's just a cache lookup
    if (!keyname) return null;
    if (DecryptedPrivateKeyCache.has(keyname)) {
        return DecryptedPrivateKeyCache.get(keyname);
    }
    logPgpTool(`Decrypted private key for '${keyname}' not in cache. Load keys with password first.`, 'warn', keyname);
    return null;
}

/**
 * Retrieves the armored public key for a given keyname from localStorage.
 * @param {string} keyname - The name of the key pair.
 * @returns {string|null} The armored public key string or null if not found.
 */
function getPublicKeyArmored(keyname) {
    if (!keyname) return null;
    return localStorage.getItem(getPublicKeyLsKey(keyname));
}

/**
 * Signs a message with the private key associated with keyname.
 * @param {string} keyname - The name of the key pair to use for signing.
 * @param {string} dataToSign - The string data to sign.
 * @returns {Promise<{publicKeyArmored: string, signature: string}|null>} Object with public key and signed message, or null on error.
 */
async function signMessage(keyname, dataToSign) {
    logPgpTool(`Attempting to sign message using key '${keyname}'...`, 'info', keyname);
    if (!isPgpReady(keyname)) {
        logPgpTool(`Keys for '${keyname}' not ready for signing. Load with password first.`, 'error', keyname);
        return null;
    }
    if (typeof dataToSign !== 'string') {
        logPgpTool('Data to sign must be a string.', 'error', keyname);
        return null;
    }

    try {
        const privateKeyObject = DecryptedPrivateKeyCache.get(keyname);
        const publicKeyArmored = getPublicKeyArmored(keyname);

        if (!privateKeyObject || !publicKeyArmored) {
             logPgpTool(`Could not retrieve keys for signing with '${keyname}'.`, 'error', keyname);
             return null;
        }

        const signedMessageArmored = await openpgp.sign({
            message: await openpgp.createMessage({ text: dataToSign }),
            signingKeys: privateKeyObject,
            detached: false,
            format: 'armored'
        });

        logPgpTool(`Message signed successfully with key '${keyname}'.`, 'success', keyname);
        return {
            publicKeyArmored: publicKeyArmored,
            signature: signedMessageArmored
        };
    } catch (error) {
        logPgpTool(`Error signing message with key '${keyname}': ${error.message}`, 'error', keyname);
        console.error(error);
        return null;
    }
}

/**
 * Verifies a PGP signed message against a given public key.
 * @param {string} publicKeyArmored - The armored public key of the signer.
 * @param {string} signedMessageArmored - The armored signed message.
 * @returns {Promise<boolean>} True if the signature is valid, false otherwise.
 */
async function verifySignature(publicKeyArmored, signedMessageArmored) {
    logPgpTool(`Attempting to verify signature...`, 'info');
    if (!publicKeyArmored || !signedMessageArmored) {
        logPgpTool('Public key and signed message are required for verification.', 'error');
        return false;
    }

    try {
        const verificationKeys = await openpgp.readKey({ armoredKey: publicKeyArmored });
        const verificationResult = await openpgp.verify({
            message: await openpgp.readMessage({ armoredMessage: signedMessageArmored }),
            verificationKeys: verificationKeys
        });

        if (!verificationResult.signatures || verificationResult.signatures.length === 0) {
            logPgpTool('No signatures found in the message.', 'warn');
            return false;
        }
        for (const sig of verificationResult.signatures) {
            if (sig.keyID.equals(verificationKeys.getKeyID())) {
                if (await sig.verified) {
                    logPgpTool('Signature VERIFIED successfully.', 'success');
                    return true;
                }
            }
        }
        logPgpTool('Signature verification FAILED.', 'warn');
        return false;
    } catch (error) {
        logPgpTool(`Error verifying signature: ${error.message}`, 'error');
        console.error(error);
        return false;
    }
}

/**
 * Deletes a key pair from localStorage and cache.
 * @param {string} keyname - The name of the key pair to delete.
 * @returns {boolean} True if keys were found and deleted.
 */
function deleteKeys(keyname) {
    logPgpTool(`Attempting to delete keys for '${keyname}'...`, 'info', keyname);
    if (!keyname) return false;
    let deleted = false;
    if (localStorage.getItem(getPublicKeyLsKey(keyname))) { localStorage.removeItem(getPublicKeyLsKey(keyname)); deleted = true; }
    if (localStorage.getItem(getPrivateKeyLsKey(keyname))) { localStorage.removeItem(getPrivateKeyLsKey(keyname)); deleted = true; }
    if (DecryptedPrivateKeyCache.has(keyname)) { DecryptedPrivateKeyCache.delete(keyname); deleted = true; }
    if(deleted) logPgpTool(`Keys for '${keyname}' deleted.`, 'success', keyname);
    else logPgpTool(`No keys found for '${keyname}' to delete.`, 'warn', keyname);
    return deleted;
}

/**
 * Lists the names of all PGP key pairs stored.
 * @returns {string[]} An array of keynames.
 */
function listKeynames() {
    const keynames = [];
    for (let i = 0; i < localStorage.length; i++) {
        const lsKey = localStorage.key(i);
        if (lsKey && lsKey.endsWith(PGP_TOOLS_CONFIG.LS_PUBLIC_KEY_SUFFIX)) {
            keynames.push(lsKey.substring(0, lsKey.length - PGP_TOOLS_CONFIG.LS_PUBLIC_KEY_SUFFIX.length));
        }
    }
    logPgpTool(`Found keynames: ${keynames.join(', ') || 'None'}`, 'info');
    return keynames;
}

/**
 * Imports a PGP key pair from provided armored string data,
 * verifies them, encrypts the private key with a new password,
 * and stores them in localStorage.
 * @param {string} keyname - The name to associate with this imported key pair.
 * @param {string} newPasswordForStorage - The password to encrypt the imported private key for localStorage.
 * @param {string} publicKeyArmoredContent - The armored public key string content.
 * @param {string} privateKeyArmoredContent - The armored private key string content.
 * @param {string} [oldPrivateKeyPassword] - Optional: Password if the imported private key file itself is encrypted.
 * @returns {Promise<{publicKeyArmored: string, privateKeyObject: openpgp.PrivateKey}|null>}
 */
async function importKeyPair(keyname, newPasswordForStorage, publicKeyArmoredContent, privateKeyArmoredContent, oldPrivateKeyPassword = '') {
    logPgpTool(`Attempting to import key pair for '${keyname}'...`, 'info', keyname);
    if (!keyname || !newPasswordForStorage || !publicKeyArmoredContent || !privateKeyArmoredContent) {
        logPgpTool('Keyname, new password, public key content, and private key content are required for import.', 'error', keyname);
        return null;
    }

    try {
        // 1. Read the public key content
        logPgpTool('Reading public key content...', 'debug', keyname);
        const parsedPublicKey = await openpgp.readKey({ armoredKey: publicKeyArmoredContent });

        if (!parsedPublicKey) {
            throw new Error("Provided public key content could not be parsed by openpgp.readKey.");
        }
        // For v6.x, to check if it's a public key, we might check its packets or if it can be armored.
        // A more robust check involves looking at its primary key packet type.
        // PGP public key packets have tags 6 or 14.
        const pubKeyPackets = parsedPublicKey.getPublicKeyPacket ? parsedPublicKey.getPublicKeyPacket() : (parsedPublicKey.getPrimaryKeyPacket ? parsedPublicKey.getPrimaryKeyPacket() : null);
        if (!pubKeyPackets || (pubKeyPackets.tag !== 6 && pubKeyPackets.tag !== 14)) {
             // Fallback: if it can be armored, it's likely a key object.
            if (typeof parsedPublicKey.armor !== 'function') {
                 throw new Error("Provided public key content does not appear to be a valid PGP public key object.");
            }
             logPgpTool('Public key parsed, type check via armor() passed.', 'debug', keyname);
        } else {
            logPgpTool('Public key parsed, type check via packet tag passed.', 'debug', keyname);
        }
        const publicKeyArmoredToStore = await parsedPublicKey.armor();
        logPgpTool('Public key validated and re-armored.', 'debug', keyname);


        // 2. Read the private key. It might be encrypted with oldPrivateKeyPassword.
        logPgpTool('Reading private key content (will attempt decryption if password provided)...', 'debug', keyname);
        let privateKeyObject;
        try {
            // Use decryptKey directly, as it handles parsing and decryption
            privateKeyObject = await openpgp.decryptKey({
                privateKey: await openpgp.readKey({ armoredKey: privateKeyArmoredContent }), // First parse it into a Key object
                passphrase: oldPrivateKeyPassword || '' // Pass empty string if user left prompt blank
            });

            if (!privateKeyObject || !(await privateKeyObject.isDecrypted())) {
                 // If decryptKey didn't throw but key is not decrypted, it means password was wrong
                 // or key was not encrypted in the first place AND oldPrivateKeyPassword was also empty.
                 // Let's try reading without assuming encryption if oldPrivateKeyPassword was empty.
                if (!oldPrivateKeyPassword) {
                    logPgpTool('decryptKey with empty password did not result in decrypted key. Trying to read as unencrypted.', 'debug', keyname);
                    privateKeyObject = await openpgp.readPrivateKey({ armoredKey: privateKeyArmoredContent });
                    if (!privateKeyObject || (await privateKeyObject.isEncrypted())) { // isEncrypted() might be a promise
                        throw new Error("Private key is encrypted, but no (or incorrect) old password was provided/effective.");
                    }
                } else {
                    throw new Error("Failed to decrypt the provided private key with the given 'old' password.");
                }
            }
            logPgpTool('Private key read and decrypted successfully.', 'debug', keyname);

        } catch (e) {
            logPgpTool(`Error reading/decrypting provided private key file. If it was encrypted, ensure its password was correct. Error: ${e.message}`, 'error', keyname);
            throw e; // Re-throw to be caught by outer try-catch and show alert in manager.js
        }

        // For v6.x, after successful read/decrypt, check if it's a private key object
        const privKeyPackets = privateKeyObject.getPrivateKeyPacket ? privateKeyObject.getPrivateKeyPacket() : ( privateKeyObject.getPrimaryKeyPacket ? privateKeyObject.getPrimaryKeyPacket() : null);
        if (!privKeyPackets || (privKeyPackets.tag !== 5 && privKeyPackets.tag !== 7)) { // PGP private key packets have tags 5 or 7
             if (typeof privateKeyObject.toPublic !== 'function') { // Fallback check
                throw new Error("Provided private key content does not appear to be a valid PGP private key object after decryption.");
             }
             logPgpTool('Private key validated via toPublic() method.', 'debug', keyname);
        } else {
            logPgpTool('Private key validated via packet tag.', 'debug', keyname);
        }


        // 3. Verify the public key matches the private key
        logPgpTool('Verifying public key matches private key...', 'debug', keyname);
        const derivedPublicKeyFromPrivate = privateKeyObject.toPublic(); // Get public part from the (decrypted) private key object

        if (!parsedPublicKey.getKeyID().equals(derivedPublicKeyFromPrivate.getKeyID())) {
            // Also check fingerprints for more robustness if Key IDs match but keys differ (rare for well-formed keys)
            const pubFingerprint = await parsedPublicKey.getFingerprint();
            const privDerivedPubFingerprint = await derivedPublicKeyFromPrivate.getFingerprint();
            if (pubFingerprint !== privDerivedPubFingerprint) {
                throw new Error("The provided public key does not match the provided private key (fingerprint mismatch).");
            }
            logPgpTool('Public and private key KeyIDs match, fingerprints also match.', 'debug', keyname);
        } else {
             logPgpTool('Public and private key KeyIDs match.', 'debug', keyname);
        }


        // 4. Encrypt the (now decrypted) private key object with the newPasswordForStorage
        logPgpTool(`Encrypting private key with new password for storage ('${keyname}')...`, 'debug', keyname);
        const encryptedPrivateKeyResultForNewStorage = await openpgp.encryptKey({
            privateKey: privateKeyObject, // The decrypted private key object
            passphrase: newPasswordForStorage
            // No format here, assuming it defaults to armored or we armor its result
        });

        let finalEncryptedArmoredPrivateKey;
        if (typeof encryptedPrivateKeyResultForNewStorage === 'string') {
            finalEncryptedArmoredPrivateKey = encryptedPrivateKeyResultForNewStorage;
        } else if (encryptedPrivateKeyResultForNewStorage && typeof encryptedPrivateKeyResultForNewStorage.armor === 'function') {
            finalEncryptedArmoredPrivateKey = await encryptedPrivateKeyResultForNewStorage.armor();
        } else {
            throw new Error('encryptKey (for new storage) did not return an armored string or armor-able object.');
        }
        logPgpTool('Private key re-encrypted for storage.', 'debug', keyname);

        // 5. Store them
        localStorage.setItem(getPublicKeyLsKey(keyname), publicKeyArmoredToStore);
        localStorage.setItem(getPrivateKeyLsKey(keyname), finalEncryptedArmoredPrivateKey);

        DecryptedPrivateKeyCache.set(keyname, privateKeyObject);

        logPgpTool(`Key pair for '${keyname}' imported, verified, and stored successfully.`, 'success', keyname);
        
        try {
            triggerDownload(`${keyname}.pub.asc`, publicKeyArmoredToStore);
            triggerDownload(`${keyname}.priv.asc`, finalEncryptedArmoredPrivateKey);
             logPgpTool('Backup download prompts for imported key initiated.', 'info', keyname);
        } catch (downloadError) { /* ... */ }

        return {
            publicKeyArmored: publicKeyArmoredToStore,
            privateKeyObject: privateKeyObject // Return the decrypted private key object for immediate use
        };

    } catch (error) {
        logPgpTool(`Error importing key pair for '${keyname}': ${error.message}`, 'error', keyname);
        console.error(error); // Keep original error for dev console
        return null;
    }
}


const PGPTools = {
    generateKeys,
    loadKeys,
    isPgpReady,
    getPublicKeyArmored,
    getDecryptedPrivateKeyObject,
    signMessage,
    verifySignature,
    deleteKeys,
    listKeynames,
    importKeyPair, // Added function
    triggerDownload,
    getPrivateKeyLsKey,
    getPublicKeyLsKey
};

// Make it available globally if not using modules
if (typeof window !== 'undefined') {
    window.PGPTools = PGPTools;
}
// For ES module usage, you might prefer:
// export default PGPTools;
// or export const { generateKeys, ... } = PGPTools;
