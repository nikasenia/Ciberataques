# vulnTLSServer.nse – TLS Vulnerability Scanner Script

Nmap NSE script to detect vulnerabilities and bad practices in HTTPS/TLS servers.  
The script inspects:

- The **server certificate** (type, key length, validity, CN/SAN, etc.).
- The **TLS configuration** (protocol versions, cipher suites, compression).
- A set of **enhanced functionalities** related to HTTP headers and advanced TLS aspects.

---

## 1. Requirements

- **Kali Linux** VM (as provided in the lab).
- **Nmap** with NSE support (default in Kali).
- **Docker** (for the provided Apache container):
  - Image: `tc_labi_apache:latest` (from `tc_labi_apache.tar` in `~/Downloads`).
- **Metasploitable2** VM (with secure Apache and virtual hosts on 443/9443).
- Optional:
  - Browser to check `http://localhost:7001`, `https://localhost:8443`, ...

---

## 2. Script Overview

- **Script name**: `vulnTLSServer`
- **File**: `vulnTLSServer.nse`
- **Objective**:  
  Analyze the target HTTPS server and generate alerts grouped by severity levels (for basic checks) plus a separate group of enhanced functionalities.

The script should follow best practices from:
- OWASP TLS-related cheat sheets.
- Mozilla Server Side TLS Intermediate Configuration guidelines.

---

## 3. Functionalities Summary

### 3.1 Basic Certificate & TLS Checks (with severity levels)

These checks generate alerts under the 4 severity categories:

- `CRITICAL`
- `HIGH`
- `MEDIUM`
- `LOW`

The output format for each severity is:

```
****
<SEVERITY> ALERTS: <number of these severity alerts>
****
- <Title of alert1>. <Description of alert>
- <Title of alert2>. <Description of alert>
****
```

#### 3.1.1 CRITICAL Alerts

1. **Self-Signed Certificates**  
   - Condition: Certificate is self-signed (issuer == subject).
   - Reason: Only certificates signed by a trusted CA should be used (internal or public).
   - Example alert:
     - `- Self-signed certificate detected. Certificate is not signed by a trusted CA.`

2. **CBC and/or SHA Support in Cipher Suite Used**  
   - Condition: The negotiated cipher suite for the scanned TLS connection:
     - uses **CBC** mode, and/or
     - uses deprecated **SHA-1**.
   - Reason: CBC mode is vulnerable to BEAST, Lucky Thirteen, POODLE; SHA-1 is deprecated.
   - Example alert:
     - `- Cipher includes CBC mode and/or SHA-1. Vulnerable to known TLS attacks.`

3. **TLS Compression Enabled**  
   - Condition: TLS-level compression is enabled for the connection.
   - Reason: CRIME attack can recover sensitive information (like cookies).
   - Example alert:
     - `- TLS compression is enabled. Vulnerable to CRIME attack.`

#### 3.1.2 HIGH Alerts

1. **Certificate Type / Key Size**  
   - Expected:
     - `ECDSA` with `P-256`, or
     - `RSA` with **≥ 2048 bits**.
   - Condition: Certificate uses a different type or **key size < 2048 bits**.
   - Example alert:
     - `- Weak certificate key. RSA key size is 1024 bits (recommended >= 2048).`

2. **Supported Protocol Versions**  
   - Expected: Server supports **TLS 1.2 or TLS 1.3 by default**.
   - Condition:
     - Does not support TLS 1.2/1.3, and
     - Supports old protocols like TLS 1.0 or older.
   - Example alert:
     - `- Server does not support TLS 1.2 or TLS 1.3 by default.`

3. **Cipher Suites**  
   - Expected that **supported suites include** (for TLS 1.2 or older):

     - `ECDHE-ECDSA-AES128-GCM-SHA256`
     - `ECDHE-RSA-AES128-GCM-SHA256`
     - `ECDHE-ECDSA-AES256-GCM-SHA384`
     - `ECDHE-RSA-AES256-GCM-SHA384`
     - `ECDHE-ECDSA-CHACHA20-POLY1305`
     - `ECDHE-RSA-CHACHA20-POLY1305`
     - `DHE-RSA-AES128-GCM-SHA256`
     - `DHE-RSA-AES256-GCM-SHA384`
     - `DHE-RSA-CHACHA20-POLY1305`

   - Condition: Any **other** supported cipher suite triggers a high alert.
   - Example alert:
     - `- Unsupported TLS cipher: TLS_RSA_WITH_AES_128_CBC_SHA`

#### 3.1.3 MEDIUM Alerts

1. **Certificate Lifespan**  
   - Recommended validity: **90 to 366 days**.
   - Condition:
     - Certificate expires in **< 90 days**, or
     - Certificate validity period is **> 366 days**.
   - Example alert:
     - `- Certificate lifespan is 750 days (greater than recommended 366 days).`

2. **Domain Name Matching**  
   - Condition:
     - The server's domain name does **not match** the certificate CN and/or SAN.
   - Example alert:
     - `- Domain name does not match certificate CN/SAN.`

#### 3.1.4 LOW Alerts

1. **Non-Qualified Hostnames**  
   - Condition: The certificate includes non-qualified hostnames (e.g. `server`, `intranet`) instead of FQDNs.
   - Example alert:
     - `- Non-qualified hostname found in certificate.`

2. **IP Addresses in Certificate Attributes**  
   - Condition: IP addresses appear in subject CN or SAN entries.
   - Example alert:
     - `- IP address included in certificate attributes (CN/SAN).`

---

### 3.2 Enhanced Functionalities (separate category)

These checks are **not** classified as `CRITICAL/HIGH/MEDIUM/LOW` in the conceptual grouping; instead they form a distinct category: **Enhanced Functionalities**.  
Internally you can still assign severity to each alert, but in the README we document them as "Enhanced".

Proposed enhanced checks from the assignment:

1. **HSTS (HTTP Strict Transport Security)**  
   - Check:
     - Inspect the `Strict-Transport-Security` header on the HTTPS response.
   - Conditions:
     - If **no HSTS header** → High-level enhanced alert.
     - If `max-age < 63072000` (2 years) → Medium-level enhanced alert.
   - Requires:
     - Modify Apache VirtualHost to add `Header always set Strict-Transport-Security "..."`
   - Example alerts:
     - `- [ENHANCED] HSTS header not configured.`
     - `- [ENHANCED] HSTS max-age is 31536000 (less than recommended 63072000).`

2. **Server Information Disclosure**  
   - Check:
     - HTTP headers like `Server`, `X-Powered-By`, etc.
   - Condition:
     - If these headers reveal sensitive information (exact version numbers, frameworks, etc.), raise an enhanced medium-level alert.
   - Example alert:
     - `- [ENHANCED] Server header discloses version: Apache/2.4.41 (Ubuntu).`

3. **TLS Curves**  
   - Expected supported curves:
     - `X25519`
     - `prime256v1`
     - `secp384r1`
   - Condition:
     - Any other supported TLS curve should trigger a high enhanced alert listing the curve.
   - Requires:
     - Generate / use a new server certificate and configuration supporting ECDHE with specific curves.
   - Example alert:
     - `- [ENHANCED] Unsupported TLS curve detected: secp521r1.`

4. **DH Parameter Size**  
   - For **TLS 1.2 / 1.3**, DH params should be **2048 bits (ffdhe2048, RFC 7919)**.
   - Condition:
     - If DH parameter size is **< 2048**, raise a high enhanced alert.
   - Requires:
     - Adjust Apache DH parameters (e.g., custom `dhparams.pem` with different sizes).
   - Example alert:
     - `- [ENHANCED] DH parameter size is 1024 bits (recommended 2048).`

5. **Wildcard Certificate Scope**  
   - Check:
     - Presence of wildcard in CN or SAN (`*.example.com`).
   - Condition:
     - If wildcard is present, show a low enhanced alert (scope limitation / risky practice).
   - Test:
     - Issue a wildcard cert, e.g. `*.foo.example.org`, and configure Apache or Docker host.
   - Example alert:
     - `- [ENHANCED] Wildcard certificate detected in CN/SAN.`

6. **CN and SAN Attributes Alignment**  
   - Recommended:
     - Primary FQDN in CN, full list of FQDNs in SAN.
   - Condition:
     - If CN does not contain the primary FQDN or SAN does not include all relevant FQDNs, raise a low enhanced alert.
   - Test:
     - Modify certificate so CN/SAN are inconsistent and use Docker/Apache to deploy it.
   - Example alert:
     - `- [ENHANCED] CN and SAN attributes are not aligned with recommended configuration.`

7. **Cipher Preference (Server vs Client)**  
   - Check:
     - Whether the server honors its own cipher preference or lets the client choose.
   - Condition:
     - If the client chooses the cipher, raise a low enhanced alert.
   - Example alert:
     - `- [ENHANCED] Client cipher preference honored; server does not enforce its own cipher order.`

8. **Other Optional Enhancements**  
   - Based on the Trend Micro report:
     - E.g., check for certificate pinning related headers, additional security headers, etc.

---

## 4. Certificates Needed for Testing

To trigger the different alerts you will typically need:

### 4.1 Certificate 1: Baseline "Good" Certificate

- **Type**: RSA 2048 or ECDSA P-256.
- **Validity**: Reasonable validity (e.g. 180 days).
- **Identity**: FQDN in CN and SAN, no IPs, no wildcards.
- **TLS config**:
  - TLS 1.2/1.3 enabled.
  - Strong cipher suites from the recommended list.
  - No compression.
- **Purpose**:
  - Confirm that **no basic alerts** are triggered in the ideal case.
  - Use it as a control for enhanced checks (HSTS, headers, etc.).

### 4.2 Certificate 2: Weak Key / Legacy Protocol Certificate

- **Type**: RSA 1024 or old algorithm.
- **Server configured to**:
  - Support TLS 1.0.
  - Offer weak ciphers (CBC + SHA-1, etc.).
- **Purpose**:
  - Trigger `HIGH` (weak key) and `CRITICAL` (CBC/SHA, old protocols) alerts.

### 4.3 Certificate 3: Self-Signed / Misconfigured Identity Certificate

- **Type**: Self-signed certificate.
- **Identity issues**:
  - Non-qualified hostname and/or IP in CN/SAN.
  - CN and SAN mismatch or incomplete SAN.
- **Purpose**:
  - Trigger:
    - `CRITICAL`: self-signed.
    - `MEDIUM`: domain mismatch.
    - `LOW`: non-FQDNs or IPs in certificate.
    - Enhanced CN/SAN consistency alerts.

### 4.4 Certificate 4: Wildcard / Curves / DH Testing Certificates

- **Type**: Wildcard CN or SAN (`*.example.org`).
- **Curve**: ECDSA P-256 certificate to exercise curve checks.
- **DH params**: Possibly different DH params (1024 vs 2048 bits).
- **Purpose**:
  - Trigger enhanced checks:
    - Wildcard scope.
    - TLS curves.
    - DH parameter size.

> **Note**: In the final submission, all modified certificates must be included in the ZIP (`test/` + certificates) to reproduce your results.

---

## 5. Additional Configuration (Apache / Docker / Metasploitable2)

### 5.1 Docker Apache Setup

From your Kali VM:

```bash
cd ~/Downloads

# Clean previous containers
sudo docker rm -f $(sudo docker ps -q)

# Load image
sudo docker load -i tc_labi_apache.tar

# Verify image
sudo docker image ls

# Run container with fixed ports
sudo docker run -d --name tc_labi --restart always \
  -p 8888:80 \
  -p 8443:443 \
  tc_labi_apache
```

Then:

- Check `http://localhost:8888`
- Check `https://localhost:8443`

You can edit `/etc/hosts` on Kali to point different hostnames to `127.0.0.1` and test domain/CN/SAN behavior.

Apache virtual host configs in the container are under:

```bash
/etc/apache2/sites-enabled/
```

You will modify:

- **Certificates**: paths in `SSLCertificateFile`, `SSLCertificateKeyFile`, `SSLCertificateChainFile`.
- **Protocols / ciphers**: `SSLProtocol`, `SSLCipherSuite`, `SSLHonorCipherOrder`, etc.
- **HSTS & headers**: using `Header` directives (requires `mod_headers`).

### 5.2 Metasploitable2 Apache

- Uses HTTPS on ports **443** and **9443** with its own virtual hosts.
- You should run `vulnTLSServer.nse` against these ports to test your script in the lab environment.
- You may tweak its Apache config if allowed, or mainly use it as a "target with existing misconfigurations".

---

## 6. Nmap Script Usage

Basic usage:

```bash
sudo nmap -p 443 --script vulnTLSServer <target-ip>
```

### Examples:

#### 6.1 Docker Apache on localhost

```bash
sudo nmap -p 8443 --script vulnTLSServer 127.0.0.1
```

#### 6.2 Metasploitable2 Secure Apache

```bash
sudo nmap -p 443,9443 --script vulnTLSServer <metasploitable2-ip>
```

If you add script arguments, use `--script-args` (as in other NSE scripts):

```bash
sudo nmap -p 8443 --script vulnTLSServer \
  --script-args 'vulnTLSServer.debug=1' 127.0.0.1
```

---

## 7. Testing Procedures & Evidence

For the assignment, you must deliver:

- `vulnTLSServer.nse`
- A folder `test/` with pairs of files per test:
  - `testNN.txt` – description of the test.
  - `testNN.out` – `nmap -oN` output of the script.

Each `testNN.txt` should include:

- **Description**: brief explanation of what is tested (e.g. "self-signed, weak key, TLS 1.0 + CBC cipher").
- **Input**: relevant parameters (certificate properties, server config, expected behavior).
- **Output**: expected alerts/categories.
- **Command**: the exact `nmap` command executed.

### 7.1 Example Test Structure

#### Test 01: Baseline Good Configuration

- **File**: `test01.txt`
- **Description**: Baseline good configuration (expected: 0 basic alerts, only some enhanced if HSTS/server headers are not perfect).
- **Output file**: `test01.out`
- **Command**: 
  ```bash
  nmap -oN test01.out -p 8443 --script vulnTLSServer 127.0.0.1
  ```

#### Test 02: Self-Signed Certificate

- **File**: `test02.txt`
- **Description**: Self-signed certificate with non-qualified hostname and IP in CN (expected: critical + medium + low + enhanced CN/SAN).
- **Output file**: `test02.out`
- **Command**: 
  ```bash
  nmap -oN test02.out -p 8443 --script vulnTLSServer 127.0.0.1
  ```

#### Test 03: Old TLS Configuration

- **File**: `test03.txt`
- **Description**: Old TLS (1.0), CBC+SHA cipher, DH 1024, no HSTS (expected: critical + high + enhanced HSTS + enhanced DH size).
- **Output file**: `test03.out`
- **Command**: 
  ```bash
  nmap -oN test03.out -p 8443 --script vulnTLSServer 127.0.0.1
  ```

#### Test 04: Wildcard Certificate

- **File**: `test04.txt`
- **Description**: Wildcard certificate, additional curves, client cipher preference (expected: low basic/low enhanced + curves + cipher preference).
- **Output file**: `test04.out`
- **Command**: 
  ```bash
  nmap -oN test04.out -p 8443 --script vulnTLSServer 127.0.0.1
  ```

---

## 8. Debugging

To debug your script:

- Use Nmap's debugging flag:
  ```bash
  sudo nmap -p 8443 --script vulnTLSServer -d2 127.0.0.1
  ```
- Use `stdnse.debug()` inside your script to print debug messages.

---

## 9. Certificate Generation Commands

Below are the OpenSSL commands to generate the four certificates described in section 4.

### 9.1 Create a Certificate Authority (CA)

First, create a simple CA to sign your certificates (optional for self-signed tests):

```bash
# Generate CA private key
openssl genrsa -out ca-key.pem 4096

# Generate CA certificate
openssl req -new -x509 -days 3650 -key ca-key.pem -out ca-cert.pem \
  -subj "/C=ES/ST=Madrid/L=Madrid/O=TestCA/CN=Test CA"
```

### 9.2 Certificate 1: Baseline "Good" Certificate (RSA 2048, 180 days)

```bash
# Generate private key
openssl genrsa -out cert1-key.pem 2048

# Create CSR
openssl req -new -key cert1-key.pem -out cert1.csr \
  -subj "/C=ES/ST=Madrid/L=Madrid/O=TestOrg/CN=secure.example.com"

# Create SAN extension file
cat > cert1-san.ext << EOF
subjectAltName = DNS:secure.example.com,DNS:www.secure.example.com
EOF

# Sign certificate (180 days validity)
openssl x509 -req -in cert1.csr -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out cert1-cert.pem -days 180 \
  -extfile cert1-san.ext

# Verify
openssl x509 -in cert1-cert.pem -text -noout
```

### 9.3 Certificate 2: Weak Key (RSA 1024)

```bash
# Generate weak private key (1024 bits)
openssl genrsa -out cert2-key.pem 1024

# Create CSR
openssl req -new -key cert2-key.pem -out cert2.csr \
  -subj "/C=ES/ST=Madrid/L=Madrid/O=WeakOrg/CN=weak.example.com"

# Create SAN extension file
cat > cert2-san.ext << EOF
subjectAltName = DNS:weak.example.com
EOF

# Sign certificate
openssl x509 -req -in cert2.csr -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out cert2-cert.pem -days 365 \
  -extfile cert2-san.ext

# Verify
openssl x509 -in cert2-cert.pem -text -noout | grep "Public-Key"
```

### 9.4 Certificate 3: Self-Signed with Misconfigurations

```bash
# Generate private key
openssl genrsa -out cert3-key.pem 2048

# Create self-signed certificate with IP and non-qualified hostname
openssl req -new -x509 -key cert3-key.pem -out cert3-cert.pem -days 365 \
  -subj "/C=ES/ST=Madrid/L=Madrid/O=SelfSignedOrg/CN=192.168.1.100" \
  -addext "subjectAltName = DNS:server,IP:192.168.1.100"

# Verify
openssl x509 -in cert3-cert.pem -text -noout
```

### 9.5 Certificate 4: Wildcard Certificate (ECDSA P-256)

```bash
# Generate ECDSA private key (P-256)
openssl ecparam -name prime256v1 -genkey -out cert4-key.pem

# Create CSR with wildcard
openssl req -new -key cert4-key.pem -out cert4.csr \
  -subj "/C=ES/ST=Madrid/L=Madrid/O=WildcardOrg/CN=*.example.org"

# Create SAN extension file with wildcard
cat > cert4-san.ext << EOF
subjectAltName = DNS:*.example.org,DNS:example.org
EOF

# Sign certificate
openssl x509 -req -in cert4.csr -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out cert4-cert.pem -days 365 \
  -extfile cert4-san.ext

# Verify
openssl x509 -in cert4-cert.pem -text -noout
```

### 9.6 Verification Commands

```bash
# Check certificate details
openssl x509 -in <cert-file>.pem -text -noout

# Check key type and size
openssl rsa -in <key-file>.pem -text -noout  # For RSA
openssl ec -in <key-file>.pem -text -noout   # For ECDSA

# Verify certificate against CA
openssl verify -CAfile ca-cert.pem <cert-file>.pem

# Check certificate dates
openssl x509 -in <cert-file>.pem -noout -dates

# Check SAN
openssl x509 -in <cert-file>.pem -noout -ext subjectAltName
```

---

## 10. Apache Configuration Examples

### 10.1 Basic HTTPS VirtualHost

```apache
<VirtualHost *:443>
    ServerName secure.example.com
    DocumentRoot /var/www/html

    SSLEngine on
    SSLCertificateFile /path/to/cert1-cert.pem
    SSLCertificateKeyFile /path/to/cert1-key.pem
    SSLCertificateChainFile /path/to/ca-cert.pem

    # Strong protocols
    SSLProtocol -all +TLSv1.2 +TLSv1.3

    # Strong cipher suites
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384

    # Server cipher preference
    SSLHonorCipherOrder on

    # Disable compression
    SSLCompression off

    # HSTS header (enhanced functionality)
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains"

    # Hide server version (enhanced functionality)
    ServerTokens Prod
    ServerSignature Off
</VirtualHost>
```

### 10.2 Weak Configuration (for testing)

```apache
<VirtualHost *:8443>
    ServerName weak.example.com
    DocumentRoot /var/www/html

    SSLEngine on
    SSLCertificateFile /path/to/cert2-cert.pem
    SSLCertificateKeyFile /path/to/cert2-key.pem

    # Old protocols
    SSLProtocol -all +TLSv1.0 +TLSv1.1

    # Weak cipher suites
    SSLCipherSuite AES128-SHA:AES256-SHA:DES-CBC3-SHA

    # Client cipher preference
    SSLHonorCipherOrder off

    # Enable compression (vulnerable to CRIME)
    SSLCompression on

    # No HSTS
    # No security headers
</VirtualHost>
```

### 10.3 DH Parameters Configuration

```bash
# Generate custom DH parameters (1024 for testing weak config)
openssl dhparam -out dhparams1024.pem 1024

# Generate strong DH parameters (2048)
openssl dhparam -out dhparams2048.pem 2048
```

Add to Apache config:

```apache
SSLOpenSSLConfCmd DHParameters /path/to/dhparams2048.pem
```

### 10.4 TLS Curves Configuration

```apache
# Specify supported curves (enhanced functionality)
SSLOpenSSLConfCmd Curves X25519:prime256v1:secp384r1
```

---
