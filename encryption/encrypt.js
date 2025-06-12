#!/usr/bin/env node

const { spawn } = require('child_process');
const readline = require('readline');
const fs = require('fs').promises;
const path = require('path');
const { existsSync } = require('fs');

// Helper function to ask questions
const ask = (query) => {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  return new Promise(resolve => rl.question(query, answer => {
    rl.close();
    resolve(answer);
  }));
};

// Function to run a command and return a promise
const runCommand = (command, args) => {
  return new Promise((resolve, reject) => {
    console.log(`\n⚙️  Running: ${command} ${args.join(' ')}`);
    console.log(`--- ${command} Output ---`);

    const process = spawn(command, args, { stdio: 'inherit' });

    process.on('close', (code) => {
      console.log(`--- End of ${command} Output ---`);
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`${command} process exited with error code ${code}.`));
      }
    });

    process.on('error', (err) => {
      if (err.code === 'ENOENT') {
        reject(new Error(`Fatal Error: The "${command}" command was not found. Please ensure it is installed and in your PATH.`));
      } else {
        reject(err);
      }
    });
  });
};


// --- Main function to run the script ---
async function run() {
  const inputFile = process.argv[2];
  if (!inputFile) {
    throw new Error('Please provide a file to encrypt.\nUsage: ./encrypt.js <file-to-encrypt>');
  }

  if (!existsSync(inputFile)) {
    throw new Error(`The file "${inputFile}" does not exist.`);
  }

  console.log(`Encrypting: ${path.basename(inputFile)}`);
  const rawName = await ask('Name for archive: ');
  const password = await ask('Password: ');

  if (!rawName.trim() || !password.trim()) {
    throw new Error('Archive name and password cannot be empty.');
  }

  let outputName = rawName.trim();
  if (!outputName.toLowerCase().endsWith('.7z')) {
    outputName += '.7z';
  }

  const sevenZipArgs = [
    'a', '-mx=9', '-mhe=on', `-p${password}`, outputName, inputFile,
  ];
  
  await runCommand('7z', sevenZipArgs);
  console.log(`\n✅ Success! File encrypted to "${outputName}"`);

  // --- Secure Delete Logic using shred ---
  const deleteAnswer = await ask('\n❓ Securely delete original file? (y/n): ');
  if (deleteAnswer.toLowerCase().trim() === 'y') {
    try {
      console.log(`\n🧼 Securely shredding original file: ${inputFile}`);
      // shred -u deletes the file after overwriting.
      // shred -z adds a final overwrite with zeros to hide shredding.
      await runCommand('shred', ['-u', '-z', inputFile]); 
      console.log('✅ Secure shred complete.');

    } catch (err) {
      console.error(`\n❌ Error during secure delete process: ${err.message}`);
    }
  } else {
    console.log('\n👍 Original file kept.');
  }
}

run().catch(err => {
  console.error(`\n❌ Fatal Error: ${err.message}`);
  process.exit(1);
});
