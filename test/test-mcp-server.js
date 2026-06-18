const url = 'https://www.google.com';

console.log('--- MCP Child Process starting ---');
console.log('Environment variables:');
console.log('  NODE_EXTRA_CA_CERTS:', process.env.NODE_EXTRA_CA_CERTS);
console.log('  SSL_CERT_FILE:', process.env.SSL_CERT_FILE);
console.log('  HTTPS_PROXY:', process.env.HTTPS_PROXY);

fetch(url)
  .then(res => {
    if (res.ok) {
      console.log('MCP Child HTTPS Request: SUCCESS');
    } else {
      console.log('MCP Child HTTPS Request: FAILED with status', res.status);
    }
  })
  .catch(err => {
    console.error('MCP Child HTTPS Request: ERROR:', err.message);
  });
