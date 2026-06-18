# CertSync Integration Test Suite & Simulation Framework

This directory contains a complete, automated integration test suite to verify CertSync's CA certificate injection capabilities under stripped environment contexts (e.g., custom environment child process spawns).

---

## 1. Simulation Architecture

The test environment consists of a two-service `docker-compose` stack:

1.  **`mitmproxy` Service:**
    *   Runs a local TLS-intercepting proxy (`mitmdump`) on port 8080.
    *   Generates a custom root CA certificate dynamically at startup, saved to `./certs/mitmproxy-ca-cert.pem`.
2.  **`devcontainer` Service:**
    *   Simulates a typical development container running as a non-root `node` user with passwordless `sudo` access.
    *   All outbound requests are forced through the `mitmproxy` container via proxy environment variables.
    *   Pre-configured with multiple runtimes:
        *   **System Node.js:** Installed globally at `/usr/local/bin/node` (Node.js v22).
        *   **NVM (Node Version Manager):** Installed and configured with Node.js v22 (and v20).
        *   **Volta:** Installed and managing Node.js v22.
        *   **Java OpenJDK 17:** Headless JDK environment.

---

## 2. Test Scripts

*   `reproduce.js`: Orchestrates a parent-process HTTP fetch, an external `curl` subprocess, and two MCP server spawns:
    1.  An inherited spawn (`{ ...process.env }`).
    2.  An adversarial/stripped spawn (only forwarding proxy variables and `PATH`, completely omitting CA environment variables).
*   `test-mcp-server.js`: A mock MCP child server that executes a secure HTTP fetch and logs variables.
*   `TestConnection.java` (generated during tests): A Java connection test that triggers `HttpsURLConnection` requests through the proxy.

---

## 3. How to Run the Tests

To run the suite on a machine with Docker and WSL/Linux:

1.  **Trust the CA on the Host:**
    Copy the proxy CA to the host trust store so `certsync init` can detect it:
    ```bash
    cp ./certs/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
    update-ca-certificates
    ```
2.  **Generate Overlay:**
    Compile the binary and run `certsync up`:
    ```bash
    certsync init
    certsync up --all-mitm
    ```
3.  **Boot Stack & Run Feature Installation:**
    Boot the compose stack and copy the generated installer files:
    ```bash
    docker-compose up -d
    docker cp ~/.certsync/ca-inject/bundle.pem test_devcontainer_1:/tmp/certsync-bundle.pem
    docker cp ~/.certsync/ca-inject/install.sh test_devcontainer_1:/tmp/install.sh
    docker exec -u root test_devcontainer_1 sh /tmp/install.sh
    ```
4.  **Run Sudo Self-Escalation Test:**
    Verify the script runs dynamically as a non-root user (postStartCommand):
    ```bash
    docker exec -u node test_devcontainer_1 /usr/local/bin/certsync-inject
    ```

---

## 4. Observed Verification Outputs

When fully verified, execution results show complete CA trust across all runtimes under a stripped environment (`env -i`):

### Node.js (System, NVM, and Volta)
Running `env -i` with node binaries loads the custom CertSync shims and intercepts the CA variables correctly:

```bash
$ docker exec -u node test_devcontainer_1 env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin http_proxy=http://mitmproxy:8080 https_proxy=http://mitmproxy:8080 /usr/local/bin/node /workspace/reproduce.js

=== Parent Process Started ===
Parent Environment:
  NODE_EXTRA_CA_CERTS: /etc/ssl/certs/ca-certificates.crt
  SSL_CERT_FILE: undefined
  HTTPS_PROXY: undefined

--- 1. Testing Parent Process Fetch ---
Parent Process Fetch: SUCCESS

--- 2. Testing Code-Execution Subprocess (curl via execSync) ---
Code-Execution Subprocess (curl): SUCCESS

--- 3. Testing MCP Child Process Spawn (env option: Inherited (process.env)) ---
--- MCP Child Process starting ---
Environment variables:
  NODE_EXTRA_CA_CERTS: /etc/ssl/certs/ca-certificates.crt
  SSL_CERT_FILE: undefined
  HTTPS_PROXY: undefined
MCP Child HTTPS Request: SUCCESS
MCP Child Process closed with code 0

--- 3. Testing MCP Child Process Spawn (env option: Sanitized/Stripped CA env (e.g. only passing proxy and PATH)) ---
--- MCP Child Process starting ---
Environment variables:
  NODE_EXTRA_CA_CERTS: /etc/ssl/certs/ca-certificates.crt
  SSL_CERT_FILE: undefined
  HTTPS_PROXY: undefined
MCP Child HTTPS Request: SUCCESS
MCP Child Process closed with code 0
```

### Java OpenJDK 17
Running Java under `env -i` successfully trusts the keystore `/usr/lib/jvm/java-17-openjdk-amd64/lib/security/cacerts` (which was updated by `keytool`):

```bash
$ docker exec -u node test_devcontainer_1 env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin java -Dhttps.proxyHost=mitmproxy -Dhttps.proxyPort=8080 /workspace/TestConnection.java

=== Java TLS Connection Test ===
https.proxyHost: mitmproxy
https.proxyPort: 8080
Java HTTPS Request: SUCCESS (Status 200)
```
