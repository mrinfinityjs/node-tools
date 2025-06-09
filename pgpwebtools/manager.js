// manager.js

document.addEventListener('DOMContentLoaded', () => {
    if (typeof PGPTools === 'undefined' || typeof openpgp === 'undefined') {
        alert("FATAL ERROR: PGPTools or OpenPGP.js not loaded. Please check script inclusions and console.");
        return;
    }

    // --- UI Elements ---
    const keyNameInput = document.getElementById('keyNameInput');
    const keyPasswordInput = document.getElementById('keyPasswordInput');
    const generateKeyBtn = document.getElementById('generateKeyBtn');
    const loadKeyBtn = document.getElementById('loadKeyBtn');
    const keyListDiv = document.getElementById('keyList');
    const keyDetailsSection = document.getElementById('keyDetailsSection');
    const noKeySelectedMessageDiv = document.getElementById('noKeySelectedMessage');
    const selectedKeyNameDisplay = document.getElementById('selectedKeyNameDisplay');
    const publicKeyDisplay = document.getElementById('publicKeyDisplay');
    const signSection = document.getElementById('signSection');
    const textToSignOrVerify = document.getElementById('textToSignOrVerify');
    const signTextBtn = document.getElementById('signTextBtn');
    const verifyTextBtn = document.getElementById('verifyTextBtn');
    const copySignedTextBtn = document.getElementById('copySignedTextBtn');
    const backupKeyBtn = document.getElementById('backupKeyBtn');
    const deleteKeyBtn = document.getElementById('deleteKeyBtn');
    const logContainer = document.getElementById('logContainer');

    // Import specific UI elements
    const importKeyNameInput = document.getElementById('importKeyNameInput');
    const importPublicKeyFile = document.getElementById('importPublicKeyFile');
    const importPrivateKeyFile = document.getElementById('importPrivateKeyFile');
    const importKeyPasswordInput = document.getElementById('importKeyPasswordInput');
    const importKeysBtn = document.getElementById('importKeysBtn');


    let currentSelectedKeyName = null;
    let currentSelectedPassword = null;

    // --- Logging ---
    function logToScreen(message, type = 'info') {
        // PGPTools.isPgpReady(''); // Removed to avoid potential early call error before PGPTools fully init from its own script
        console.log(`[MANAGER UI - ${type.toUpperCase()}] ${message}`);
        const logEntry = document.createElement('div');
        logEntry.classList.add('log-entry', type);
        logEntry.textContent = `${new Date().toLocaleTimeString()} - ${message}`;
        if (logContainer) { // Ensure logContainer exists
            logContainer.insertBefore(logEntry, logContainer.firstChild);
        }
    }

    // --- Key List Management ---
    function populateKeyList() {
        // ... (populateKeyList function remains the same as before) ...
        const keynames = PGPTools.listKeynames();
        keyListDiv.innerHTML = ''; 

        if (keynames.length === 0) {
            keyListDiv.innerHTML = '<div class="list-group-item text-muted">No keys stored. Generate one!</div>';
            return;
        }

        keynames.forEach(name => {
            const listItem = document.createElement('a');
            listItem.href = '#';
            listItem.classList.add('list-group-item', 'list-group-item-action', 'bg-dark', 'text-light', 'border-secondary'); // Added theme classes
            listItem.textContent = name;
            if (name === currentSelectedKeyName) {
                listItem.classList.add('active');
            }
            listItem.onclick = (e) => {
                e.preventDefault();
                handleKeySelection(name);
            };
            keyListDiv.appendChild(listItem);
        });
    }

    async function handleKeySelection(keyname) {
        // ... (handleKeySelection function remains the same as before) ...
        //if (currentSelectedKeyName === keyname && PGPTools.isPgpReady(keyname)) {
        //    logToScreen(`Key '${keyname}' is already selected and ready.`, 'info');
        //    return;
        //}

        currentSelectedKeyName = keyname;
        currentSelectedPassword = '';
        logToScreen(`Selected key: '${keyname}'. Attempting to load/unlock...`, 'info');
        
        Array.from(keyListDiv.getElementsByClassName('list-group-item')).forEach(item => {
            item.classList.remove('active');
            if (item.textContent === keyname) {
                item.classList.add('active');
            }
        });

        if (!PGPTools.isPgpReady(keyname) || !currentSelectedPassword) { // Check if ready or if current pass is for this key
                const password = prompt(`Enter password to unlock private key for "${keyname}":`);
                if (password === null) { // User cancelled
                    logToScreen(`Password not provided for '${keyname}'. Operation cancelled.`, 'warn');
                    showKeyDetails(null); 
                    currentSelectedKeyName = null; // Deselect if cancelled
                    populateKeyList(); // Refresh list to remove active state
                    return;
                }
                if (!password) { // Empty password string
                     logToScreen(`Empty password provided for '${keyname}'. Unlock failed.`, 'warn');
                     showKeyDetails(null);
                     currentSelectedKeyName = null;
                     populateKeyList();
                     return;
                }
                currentSelectedPassword = password;
        }
        
        const keyPairInfo = await PGPTools.loadKeys(keyname, currentSelectedPassword);

        if (keyPairInfo) {
            logToScreen(`Key '${keyname}' unlocked and ready.`, 'success');
            showKeyDetails(keyname, keyPairInfo.publicKeyArmored);
            //sessionStorage.setItem(`pass_${keyname}`, currentSelectedPassword); // Cache password for session
            if (currentSelectedPassword) {
                delete currentSelectedPassword;
            }
        } else {
            logToScreen(`Failed to unlock key '${keyname}'. Incorrect password or key issue.`, 'error');
            currentSelectedPassword = null; 
            //sessionStorage.removeItem(`pass_${keyname}`);
            showKeyDetails(null);
            // If load fails, deselect the key visually
            Array.from(keyListDiv.getElementsByClassName('list-group-item')).forEach(item => {
                if (item.textContent === keyname) {
                    item.classList.remove('active');
                }
            });
            currentSelectedKeyName = null;

        }
    }

    function showKeyDetails(keyname, publicKeyArmoredStr = null) {
        // ... (showKeyDetails function remains the same as before) ...
        if (keyname && publicKeyArmoredStr) {
            selectedKeyNameDisplay.textContent = keyname;
            publicKeyDisplay.value = publicKeyArmoredStr;
            keyDetailsSection.style.display = 'block';
            noKeySelectedMessageDiv.style.display = 'none';

            if (PGPTools.isPgpReady(keyname)) {
                signSection.style.display = 'block';
            } else {
                signSection.style.display = 'none';
            }
        } else {
            selectedKeyNameDisplay.textContent = '';
            publicKeyDisplay.value = '';
            keyDetailsSection.style.display = 'none';
            signSection.style.display = 'none';
            noKeySelectedMessageDiv.style.display = 'block';
            // currentSelectedKeyName = null; // Don't nullify here, handleKeySelection does it
            // currentSelectedPassword = null;
        }
    }

    // --- Button Event Handlers ---
    generateKeyBtn.onclick = async () => {
        // ... (generateKeyBtn.onclick remains the same as before) ...
        const keyname = keyNameInput.value.trim();
        const password = keyPasswordInput.value;

        if (!keyname || !password) {
            alert('Please provide both a Key Name and a Password.');
            logToScreen('Key Name and Password required for generation.', 'warn');
            return;
        }

        logToScreen(`Generating key for '${keyname}'... This might take a moment.`, 'info');
        const keyPairInfo = await PGPTools.generateKeys(keyname, password);
        if (keyPairInfo) {
            logToScreen(`Successfully generated and stored key for '${keyname}'. Downloads initiated.`, 'success');
            alert(`Key for '${keyname}' generated! IMPORTANT: Two files (.pub.asc and .priv.asc) should have started downloading. Please save them securely and remember your password ('${password}')! The .priv.asc file is your encrypted private key.`);
            keyNameInput.value = '';
            keyPasswordInput.value = '';
            populateKeyList();
            currentSelectedPassword = password; // Store for this newly generated key for the session
            //sessionStorage.setItem(`pass_${keyname}`, password);
            handleKeySelection(keyname); // Auto-select
        } else {
            logToScreen(`Failed to generate key for '${keyname}'. Check console for details.`, 'error');
            alert(`Failed to generate key for '${keyname}'. See activity log or browser console.`);
        }
    };

    loadKeyBtn.onclick = async () => {
        // ... (loadKeyBtn.onclick remains the same as before) ...
        const keyname = keyNameInput.value.trim();
        const password = keyPasswordInput.value;
        if (!keyname || !password) {
            alert('Please provide Key Name and Password to load.');
            logToScreen('Key Name and Password required to load.', 'warn');
            return;
        }
        currentSelectedPassword = password; 
        await handleKeySelection(keyname); // handleKeySelection will now prompt if needed or use currentSelectedPassword
    };

    // --- CORRECTED Event Handler for Importing Keys ---
    importKeysBtn.onclick = async () => {
        const keyname = importKeyNameInput.value.trim();
        const newPasswordForStorage = importKeyPasswordInput.value; // Password to encrypt the key for OUR localStorage
        const pubFile = importPublicKeyFile.files[0];
        const privFile = importPrivateKeyFile.files[0];

        if (!keyname || !newPasswordForStorage || !pubFile || !privFile) {
            alert('Please provide a "Key Name for Imported Key", a "Password for New Storage", and select both Public and Private key files.');
            logToScreen('Missing fields for key import.', 'warn');
            return;
        }

        logToScreen(`Attempting to import keys as '${keyname}'...`, 'info');

        try {
            const publicKeyArmoredContent = await pubFile.text();
            const privateKeyArmoredContent = await privFile.text();

            let oldPrivKeyPassword = '';
            const looksEncrypted = privateKeyArmoredContent.includes('Proc-Type: 4,ENCRYPTED') ||
                                 privateKeyArmoredContent.includes('DEK-Info:');
            logToScreen(`Private key content check for encryption headers: FoundEncryptedHeaders=${looksEncrypted}`, 'debug');
    
            //if (looksEncrypted) {
                logToScreen('FORCING prompt for old private key password for debugging.', 'warn'); // DEBUG
                oldPrivKeyPassword = prompt(`The selected private key file ('${privFile.name}') is assumed to be encrypted. Please enter its CURRENT password to decrypt it for import:`);
        
                if (oldPrivKeyPassword === null) { // User pressed Cancel
                    logToScreen("Import cancelled by user at private key password prompt.", "info");
                    return;
                }
                logToScreen(`User provided old private key password: '${oldPrivKeyPassword}' (length: ${oldPrivKeyPassword ? oldPrivKeyPassword.length : 0})`, 'debug');
            //} else {
            //    logToScreen('Private key file does NOT appear to be encrypted based on headers. Proceeding without old password.', 'info');
           // }
    
            logToScreen(`Calling PGPTools.importKeyPair for '${keyname}' with oldPrivKeyPassword='${oldPrivKeyPassword || ""}'...`, 'debug');
            const importedKeyPair = await PGPTools.importKeyPair(
                keyname,
                newPasswordForStorage,
                publicKeyArmoredContent,
                privateKeyArmoredContent,
                oldPrivKeyPassword || '' // Ensure empty string if null
            );

            if (importedKeyPair) {
                logToScreen(`Successfully imported and stored key pair as '${keyname}'.`, 'success');
                alert(`Key pair '${keyname}' imported successfully! Backup downloads initiated. Remember the new storage password you set: '${newPasswordForStorage}'`);
                
                importKeyNameInput.value = '';
                importPublicKeyFile.value = ''; 
                importPrivateKeyFile.value = ''; 
                importKeyPasswordInput.value = '';
                
                populateKeyList();
                currentSelectedPassword = newPasswordForStorage; // Store for this session
                //sessionStorage.setItem(`pass_${keyname}`, newPasswordForStorage);
                handleKeySelection(keyname); // Auto-select the new key
            } else {
                logToScreen(`Failed to import key pair as '${keyname}'. PGPTools.importKeyPair returned null. Check logs for details.`, 'error');
                alert(`Failed to import key pair as '${keyname}'. See activity log or browser console for errors from PGPTools.`);
            }
        } catch (fileReadError) {
            logToScreen(`Error reading key files: ${fileReadError.message}`, 'error');
            alert(`Error reading key files. Ensure you selected valid text files. Details: ${fileReadError.message}`);
            console.error(fileReadError);
        }
        await handleKeySelection(keyname);
    };


    signTextBtn.onclick = async () => {
        // ... (signTextBtn.onclick remains the same as before) ...
        if (!currentSelectedKeyName || !PGPTools.isPgpReady(currentSelectedKeyName)) {
            alert('No key selected or key not ready (unlock it first).');
            logToScreen('Cannot sign: No key selected or key not unlocked.', 'warn');
            return;
        }
        let text = textToSignOrVerify.value;
        if (!text.trim()) {
            alert('Nothing to sign. Please enter some text.');
            logToScreen('Sign attempt with empty text area.', 'warn');
            return;
        }
        if (text.startsWith("-----BEGIN PGP SIGNED MESSAGE-----") || text.startsWith("-----BEGIN PGP MESSAGE-----") || text.startsWith("-----BEGIN PGP SIGNATURE-----")) {
            alert('Text already appears to be a PGP block. Please sign plain text.');
            logToScreen('Attempted to sign text that looks like a PGP block.', 'error');
            return;
        }

        logToScreen(`Signing text with key '${currentSelectedKeyName}'...`, 'info');
        const signedResult = await PGPTools.signMessage(currentSelectedKeyName, text);
        if (signedResult && signedResult.signature) {
            textToSignOrVerify.value = signedResult.signature;
            logToScreen('Text signed successfully.', 'success');
        } else {
            logToScreen('Failed to sign text.', 'error');
            alert('Signing failed. See activity log or console.');
        }
    };
    
    verifyTextBtn.onclick = async () => {
        // ... (verifyTextBtn.onclick remains the same as before) ...
        if (!currentSelectedKeyName) {
            alert('No key selected to verify against its public key.');
            logToScreen('Cannot verify: No key selected for public key context.', 'warn');
            return;
        }
        const publicKeyArmored = PGPTools.getPublicKeyArmored(currentSelectedKeyName);
        if (!publicKeyArmored) {
             alert('Could not retrieve public key for selected key name.');
             logToScreen('Cannot verify: Public key not found for selected key.', 'error');
             return;
        }

        const signedMessageArmored = textToSignOrVerify.value;
        if (!signedMessageArmored.trim() || !signedMessageArmored.includes("-----BEGIN PGP")) {
            alert('Please paste a PGP signed message or PGP message into the text area to verify.');
            logToScreen('Verify attempt with non-PGP-like text.', 'warn');
            return;
        }

        logToScreen(`Verifying message against public key of '${currentSelectedKeyName}'...`, 'info');
        const isValid = await PGPTools.verifySignature(publicKeyArmored, signedMessageArmored);
        if (isValid) {
            logToScreen('SIGNATURE VERIFIED successfully with the selected public key.', 'success');
            alert('Signature is VALID and was made by the selected key.');
        } else {
            logToScreen('SIGNATURE VERIFICATION FAILED or not made by the selected key.', 'error');
            alert('Signature is INVALID or was NOT made by the selected key.');
        }
    };

    copySignedTextBtn.onclick = () => {
        // ... (copySignedTextBtn.onclick remains the same as before) ...
        if (!textToSignOrVerify.value) {
            logToScreen('Nothing to copy from text area.', 'warn');
            return;
        }
        navigator.clipboard.writeText(textToSignOrVerify.value)
            .then(() => {
                logToScreen('Output text copied to clipboard.', 'success');
                alert('Output copied to clipboard!');
            })
            .catch(err => {
                logToScreen('Failed to copy text: ' + err, 'error');
                alert('Failed to copy. Your browser might not support this, or permissions denied. You can manually copy.');
            });
    };

    backupKeyBtn.onclick = () => {
        // ... (backupKeyBtn.onclick remains the same as before, ensure PGPTools.triggerDownload is accessible) ...
        if (!currentSelectedKeyName) {
            alert('Please select a key to backup.');
            logToScreen('Backup attempt without a selected key.', 'warn');
            return;
        }
        logToScreen(`Initiating backup for key '${currentSelectedKeyName}'...`, 'info');
        const pubKey = PGPTools.getPublicKeyArmored(currentSelectedKeyName);
        // For backup, we read the encrypted private key directly from localStorage
        // PGPTools.getDecryptedPrivateKeyObject() gives the live decrypted object, not what's stored.
        const privKeyEnc = localStorage.getItem(PGPTools.getPrivateKeyLsKey(currentSelectedKeyName)); // Assuming getPrivateKeyLsKey is exposed or replicated

        if (pubKey && typeof PGPTools.triggerDownload === 'function') PGPTools.triggerDownload(`${currentSelectedKeyName}.pub.asc`, pubKey);
        else if (pubKey) triggerDownload(`${currentSelectedKeyName}.pub.asc`, pubKey); // If triggerDownload is global in manager.js

        if (privKeyEnc && typeof PGPTools.triggerDownload === 'function') PGPTools.triggerDownload(`${currentSelectedKeyName}.priv.asc`, privKeyEnc);
        else if (privKeyEnc) triggerDownload(`${currentSelectedKeyName}.priv.asc`, privKeyEnc);
        
        if(!pubKey && !privKeyEnc){
            logToScreen(`No key data found for backup for '${currentSelectedKeyName}'. This is unexpected.`, 'error');
        } else {
            alert(`Backup downloads for '${currentSelectedKeyName}' initiated. Save the .pub.asc and .priv.asc files securely. The .priv.asc is encrypted with the password you used for this key.`);
        }
    };

    deleteKeyBtn.onclick = () => {
        // ... (deleteKeyBtn.onclick remains the same as before) ...
        if (!currentSelectedKeyName) {
            alert('Please select a key to delete.');
            logToScreen('Delete attempt without a selected key.', 'warn');
            return;
        }
        if (confirm(`Are you sure you want to permanently delete the key pair "${currentSelectedKeyName}"? This cannot be undone!`)) {
            logToScreen(`Deleting key '${currentSelectedKeyName}'...`, 'info');
            const deleted = PGPTools.deleteKeys(currentSelectedKeyName);
            if (deleted) {
                logToScreen(`Key '${currentSelectedKeyName}' deleted successfully.`, 'success');
                currentSelectedKeyName = null;
                currentSelectedPassword = null;
                //sessionStorage.removeItem(`pass_${currentSelectedKeyName}`); // Clear session pass
                populateKeyList();
                showKeyDetails(null); 
                textToSignOrVerify.value = ''; 
            } else {
                logToScreen(`Failed to delete key '${currentSelectedKeyName}'. It might not have existed.`, 'warn');
            }
        }
    };

    // --- Initial Load ---
    populateKeyList();
    showKeyDetails(null);
    logToScreen("PGP Manager UI Initialized.", "info");
});

// Helper to get LS key name for private key, if PGPTools doesn't expose it
// This is a workaround if PGPTools.getPrivateKeyLsKey is not exposed
// It's better if PGPTools exposes necessary helpers or if backup logic is inside PGPTools
function getManagerPrivKeyLsName(keyname) {
    const LS_PRIVATE_KEY_SUFFIX = '.priv'; // Must match PGPTools
    return `${keyname}${LS_PRIVATE_KEY_SUFFIX}`;
}
// Add triggerDownload here if not exposed by PGPTools and used by backup
function triggerDownload(filename, textContent) {
    if (typeof PGPTools !== 'undefined' && typeof PGPTools.triggerDownload === 'function') {
        PGPTools.triggerDownload(filename, textContent); // Prefer PGPTools' version
        return;
    }
    // Fallback if PGPTools.triggerDownload is not exposed (should be though)
    try {
        const element = document.createElement('a');
        const file = new Blob([textContent], { type: 'text/plain;charset=utf-8' });
        element.href = URL.createObjectURL(file);
        element.download = filename;
        document.body.appendChild(element); 
        element.click();
        document.body.removeChild(element);
        URL.revokeObjectURL(element.href);
        console.log(`[MANAGER UI - INFO] Fallback download initiated for ${filename}.`);
    } catch (e) {
        console.error(`[MANAGER UI - ERROR] Fallback download error for ${filename}: ${e.message}`);
        alert(`Could not automatically start download for ${filename}.`);
    }
}
