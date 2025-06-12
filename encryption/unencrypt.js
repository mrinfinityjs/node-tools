#!/usr/bin/env node

const { spawn } = require('child_process');
const readline = require('readline');
const fs = require('fs').promises;
const path = require('path');
const { existsSync } = require('fs');

// Helper function to ask for a password without showing it on the screen
const askPassword = (query) => {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  // This little hack prevents the password from being echoed to the console
  const onDataHandler = (char) => {
    char = char.toString();
    switch (char) {
      case '\n':
      case '\r':
      case '\u0004':
        process.stdin.removeListener('data', onDataHandler);
        break;
      default:
        process.stdout.clearLine(0);
        readline.cursorTo(process.stdout, 0);
        process.stdout.write(query + Array(rl.line.length + 1).join('*'));
        break;
    }
  };
  return new Promise(resolve => {
    rl.question(query, (password) => {
      rl.close();
      process.stdin.removeListener('data', onDataHandler);
      process.stdout.write('\n'); // Add a newline after the user presses enter
      resolve(password);
    });
    process.stdin.on('data', onDataHandler);
  });
};

// --- Main function to run the script ---
async function run() {
  const inputFile = process.argv[2];
  if (!inputFile) {
    throw new Error('Please provide a .7z file to decrypt.\nUsage: node unencrypt.js <file.7z>');
  }
  if (!inputFile.toLowerCase().endsWith('.7z')) {
      throw new Error('Input file must be a .7z archive.');
  }
  if (!existsSync(inputFile)) {
    throw new Error(`The file "${inputFile}" does not exist.`);
  }

  // 1. Determine output directory
  const archiveBaseName = path.basename(inputFile, '.7z');
  const outputDir = path.join('unencrypted', archiveBaseName);

  // 2. Prompt for password
  const password = await askPassword('Password for archive: ');
  if (!password) {
      // In 7z, an empty password is valid. We assume user wants one.
      // If no password is required, the user can just press Enter.
      console.log('ℹ️  Attempting to extract without a password.');
  }

  // 3. Create the output directory
  try {
      await fs.mkdir(outputDir, { recursive: true });
  } catch (err) {
      throw new Error(`Could not create output directory "${outputDir}": ${err.message}`);
  }

  // 4. Define 7z arguments for extraction
  const sevenZipArgs = [
    'x',               // Extract with full paths
    inputFile,         // The archive to extract
    `-o${outputDir}`,  // The output directory
    '-y',              // Assume "Yes" on all queries from 7-Zip (e.g., overwrite)
  ];

  // Only add the password switch if a password was provided
  if (password) {
      sevenZipArgs.push(`-p${password}`);
  }

  console.log(`\n⚙️  Running: 7z ${sevenZipArgs.join(' ')}`);
  console.log('--- 7z Output ---');

  // 5. Execute the command
  const sevenZip = spawn('7z', sevenZipArgs, { stdio: 'inherit' });

  sevenZip.on('close', (code) => {
    console.log('--- End of Output ---');
    if (code === 0) {
      console.log(`\n✅ Success! Archive extracted to "${outputDir}"`);
    } else if (code === 2) {
      // 7z exit code 2 often means a fatal error, like a wrong password
      console.error(`\n❌ Extraction failed. This is often due to a wrong password. (Exit code ${code})`);
    } else {
        console.error(`\n❌ 7z process exited with error code ${code}. Extraction failed.`);
    }
  });

  sevenZip.on('error', (err) => {
    if (err.code === 'ENOENT') {
      console.error('\n❌ Fatal Error: The "7z" command was not found. Please make sure p7zip-full is installed.');
    } else {
      console.error('Failed to start the 7z process:', err);
    }
  });
}

run().catch(err => {
  console.error(`\n❌ Fatal Error: ${err.message}`);
  process.exit(1);
});
