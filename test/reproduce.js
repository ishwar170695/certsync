const { spawn, execSync } = require('child_process');
const path = require('path');

const url = 'https://www.google.com';

console.log('=== Parent Process Started ===');
console.log('Parent Environment:');
console.log('  NODE_EXTRA_CA_CERTS:', process.env.NODE_EXTRA_CA_CERTS);
console.log('  SSL_CERT_FILE:', process.env.SSL_CERT_FILE);
console.log('  HTTPS_PROXY:', process.env.HTTPS_PROXY);

async function runParentTest() {
  console.log('\n--- 1. Testing Parent Process Fetch ---');
  try {
    const res = await fetch(url);
    if (res.ok) {
      console.log('Parent Process Fetch: SUCCESS');
    } else {
      console.log('Parent Process Fetch: FAILED with status', res.status);
    }
  } catch (err) {
    console.error('Parent Process Fetch: ERROR:', err.message);
  }
}

function runSubprocessTest() {
  console.log('\n--- 2. Testing Code-Execution Subprocess (curl via execSync) ---');
  try {
    // Run curl. It uses HTTPS_PROXY and respects SSL_CERT_FILE.
    const output = execSync('curl -s -I https://www.google.com', { stdio: 'pipe' }).toString();
    console.log('Code-Execution Subprocess (curl): SUCCESS');
    console.log(output.split('\n')[0]);
  } catch (err) {
    console.error('Code-Execution Subprocess (curl): ERROR:', err.message);
    if (err.stderr) {
      console.error('Stderr:', err.stderr.toString());
    }
  }
}

function runMcpTest(envOptions) {
  return new Promise((resolve) => {
    console.log(`\n--- 3. Testing MCP Child Process Spawn (env option: ${envOptions.name}) ---`);
    
    // Spawn the child script
    const childEnv = envOptions.getEnv();
    const child = spawn('node', [path.join(__dirname, 'test-mcp-server.js')], {
      env: childEnv
    });

    child.stdout.on('data', (data) => {
      process.stdout.write(data.toString());
    });

    child.stderr.on('data', (data) => {
      process.stderr.write(data.toString());
    });

    child.on('close', (code) => {
      console.log(`MCP Child Process closed with code ${code}`);
      resolve();
    });
  });
}

async function main() {
  await runParentTest();
  runSubprocessTest();

  // Test 3a: MCP spawn inheriting the full process.env (default behavior)
  await runMcpTest({
    name: 'Inherited (process.env)',
    getEnv: () => ({ ...process.env })
  });

  // Test 3b: MCP spawn with custom/sanitized env (reproducing the issue)
  // Here we simulate a sanitized environment where proxy is set but CA config variables are stripped/omitted
  await runMcpTest({
    name: 'Sanitized/Stripped CA env (e.g. only passing proxy and PATH)',
    getEnv: () => ({
      PATH: process.env.PATH,
      HTTP_PROXY: process.env.HTTP_PROXY,
      HTTPS_PROXY: process.env.HTTPS_PROXY,
      http_proxy: process.env.http_proxy,
      https_proxy: process.env.https_proxy
    })
  });
}

main().catch(console.error);
