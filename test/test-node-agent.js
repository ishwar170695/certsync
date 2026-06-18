const http = require('http');
const tls = require('tls');

// Make a CONNECT request to mitmproxy
const req = http.request({
  host: 'mitmproxy',
  port: 8080,
  method: 'CONNECT',
  path: 'www.google.com:443'
});

req.on('connect', (res, socket, head) => {
  console.log('CONNECT tunnel established');
  
  // Establish TLS over the tunnel socket
  const tlsSocket = tls.connect({
    socket: socket,
    servername: 'www.google.com'
  }, () => {
    console.log('TLS handshake SUCCESS');
    tlsSocket.write('GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n');
  });

  tlsSocket.on('data', (data) => {
    console.log('Received response header:', data.toString().split('\n')[0]);
    tlsSocket.destroy();
  });

  tlsSocket.on('error', (err) => {
    console.error('TLS handshake ERROR:', err.message);
  });
});

req.on('error', (err) => {
  console.error('CONNECT request ERROR:', err.message);
});

req.end();
