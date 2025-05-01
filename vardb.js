// Save Variables to encrypted .json file on NodeJS app crash, load them at start.
// Instead of const var = {};
// Nest as many vars[as].needed.
// Not secure, but works.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const cfg = {
  sys_encryption_phrase: 'Encrypted_Password_Here_to_Store_to_Disk'
}

function ncrypt(text) {
    try {
        const iv = crypto.randomBytes(16);
        const key = crypto.scryptSync(cfg.sys_encryption_phrase, 'salt', 32);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag().toString('hex');
        
        return iv.toString('hex') + ':' + authTag + ':' + encrypted;
    } catch (error) {
        console.error('Encryption error:', error);
        throw error;
    }
}

function dcrypt(encryptedString) {
    try {
        const [ivHex, authTagHex, encrypted] = encryptedString.split(':');
        const iv = Buffer.from(ivHex, 'hex');
        const authTag = Buffer.from(authTagHex, 'hex');
        const key = crypto.scryptSync(cfg.sys_encryption_phrase, 'salt', 32);
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(authTag);
        
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        return decrypted;
    } catch (error) {
        console.error('Decryption error:', error);
        throw error;
    }
}


function ensureDirectoryExists(filePath) {
    const dirPath = path.dirname(filePath);
    if (!fs.existsSync(dirPath)) {
        fs.mkdirSync(dirPath, { recursive: true });
    }
}

function saveVar(variable, filePath, pathToVar) {
    try {
        ensureDirectoryExists(filePath);
        
        // Load existing data if it exists
        let existingData = {};
        if (fs.existsSync(filePath)) {
            const encryptedData = fs.readFileSync(filePath, 'utf8');
            const jsonData = dcrypt(encryptedData);
            existingData = JSON.parse(jsonData);
        }

        // Navigate to the specified path and set the variable
        const keys = pathToVar.split('.');
        let current = existingData;
        for (let i = 0; i < keys.length - 1; i++) {
            if (!current[keys[i]]) {
                current[keys[i]] = {};
            }
            current = current[keys[i]];
        }
        current[keys[keys.length - 1]] = variable;

        // Convert to JSON and encrypt
        const jsonData = JSON.stringify(existingData, null, 2);
        const encryptedData = ncrypt(jsonData);
        
        // Write to file
        fs.writeFileSync(filePath, encryptedData, 'utf8');
        console.log(`Variable successfully saved to ${filePath}`);
        return true;
    } catch (error) {
        console.error(`Error saving variable to ${filePath}:`, error);
        return false;
    }
}

function loadVar(filePath, pathToVar) {
    try {
        const dirPath = path.dirname(filePath);
        if (!fs.existsSync(dirPath)) {
            fs.mkdirSync(dirPath, { recursive: true });
            console.log(`Created directory: ${dirPath}`);
        }
        
        if (!fs.existsSync(filePath)) {
            console.log(`File not found: ${filePath}. Returning empty object.`);
            return {};
        }
        
        const encryptedData = fs.readFileSync(filePath, 'utf8');
        const jsonData = dcrypt(encryptedData);
        const existingData = JSON.parse(jsonData);

        // Navigate to the specified path and return the variable
        const keys = pathToVar.split('.');
        let current = existingData;
        for (const key of keys) {
            if (current[key] === undefined) {
                console.log(`Path not found: ${pathToVar}. Returning empty object.`);
                return {};
            }
            current = current[key];
        }
        console.log(`Variable successfully loaded from ${filePath}`);
        return current;
    } catch (error) {
        console.error(`Error loading variable from ${filePath}:`, error);
        return {};
    }
}



// Handle process signals for saving variables
['SIGINT', 'SIGTERM'].forEach(signal => {
    process.on(signal, () => {
        console.log(`Saving variables for later.`);
        saveVar(workshopData, path.join(__dirname, 'var', 'example'), 'example');
        process.exit(0);
    });
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
    console.log('Saving variables before crash...');
    saveVar(workshopData, path.join(__dirname, 'var', 'example'), 'example');
    process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Promise Rejection:', reason);
    console.log('Saving variables before crash...');
    saveVar(workshopData, path.join(__dirname, 'var', 'example'), 'example');
    process.exit(1);
});

const example = loadVar(path.join(__dirname, 'var', 'example.json'), 'example');

example.test = "data";
