-- vulnTLSServer.nse
-- NSE script to detect vulnerabilities in TLS/SSL servers
-- Cyber Attack Techniques Laboratory

description = [[
This script analyzes vulnerabilities in TLS/SSL servers.
It detects obsolete protocol versions, weak ciphers, and
other common security vulnerabilities.
]]

---
-- @usage
-- nmap -p 443 --script vulnTLSServer <ip-target>
--
-- @output
-- PORT   STATE SERVICE
-- 443/tcp open  https
-- | vulnTLSServer:
-- |   ****
-- |   CRITICAL ALERTS: 2
-- |   ****
-- |   - Self-signed certificate detected
-- |   - Cipher includes CBC mode and SHA hash algorithm
-- |   ****
-- |   HIGH ALERTS: 1
-- |   ****
-- |   - Unsupported TLS cipher: TLS-RSA-WITH-AES-128-CBC-SHA
-- |   ****

-- Import necessary libraries
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local sslcert = require "sslcert"
local tls = require "tls"
local http = require "http"

-- Author and license information
author = "Ignacio Ávila Reyes, Ksenia Myakisheva"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe", "discovery"}

-- Execution rule: runs on common SSL/TLS ports
portrule = shortport.ssl

-- Type of alerts
local alerts = {
  critical = {},
  high = {},
  medium = {},
  low = {}
}

-- Mozilla's Intermediate recommended Cipher suites
local recommended_ciphers = {
  "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
  "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
  "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
  "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
  "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
  "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
  "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
  "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
  "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
}

-- Function to check for self-signed certificate
-- - @param cipher_name The name of the cipher
-- - @return true if the cipher is recommended, false otherwise
local function is_cipher_recommended(cipher_name)
  for _, rec_cipher in ipairs(recommended_ciphers) do
    if string.find(cipher_name, rec_cipher) then
      return true
    end
  end
  return false
end

-- Function to verify if a cipher uses CBC mode or SHA hash algorithm
-- @param cipher_name The name of the cipher
-- @return true if CBC or SHA is found, false otherwise
local function has_cbc_or_sha(cipher_name)
  if string.find(cipher_name, "CBC") 
  or string.find(cipher_name, "SHA1")
  or string.find(cipher_name, "SHA%-") then
    return true
  end
  return false
end

-- Function to connect and get TLS info
-- @param host Target host
-- @param port Target port
-- @return table with TLS info
local function get_TLS_info(host, port)
  local sock, status, error

  -- Let's see if there's a specialized function for this port
  local specialized = sslcert.getPrepareTLSWithoutReconnect(port)

  -- Create a socket connection depending on the port
  if specialized then

    status, sock = specialized(host, port)
    if not status then 
      stdnse.debug(1, "Failed to connect: %s", sock)
      return nil
    end

  else

    sock = nmap.new_socket()
    status, error = sock:connect(host, port)
    if not status then
      stdnse.debug(1, " *** Debugging:  Failed to connect: %s ***********", error)
      return nil
    end

  end

  sock:set_timeout(5000)

  -- Send Client Hello with TLSv1.2
  local cli_h = tls.client_hello({
    protocol = "TLSv1.2",
  })

  status, error = sock:send(cli_h)
  if not status then
    stdnse.debug(1, " *** Debugging:  Send failed: %s ***********", error)
    sock:close()
    return nil
  end

  -- Read server response
  local response
  status, response, error = tls.record_buffer(sock)
  sock:close()

  if not status then
    return nil
  end

  -- Now let's parse the response to extract TLS info
  local i, record = tls.record_read(response, 1)
  if not record or record.type ~= "handshake" then
    return nil
  end

  if record.body[1].type == "server_hello" then
    return record.body[1]
  end

  return nil

end

-- Function to check for non-qualified host names in certificate
-- @param cert The certificate object
-- @return true and alert message if non-qualified host found, false otherwise
local function is_non_qualified_host(cert)
  if cert.subject.commonName then
    local cn = cert.subject.commonName
    if not string.find(cn, "%.") then
      return true, string.format("Non-qualified host name in certificate CN: %s", cn)
    end
  end

  if cert.extensions and cert.extensions.subjectAltName then
    for _, san in ipairs(cert.extensions.subjectAltName) do
      if not string.find(san, "%.") then
        return true, string.format("Non-qualified host name in certificate SAN: %s", san)
      end 
    end
  end

  return false, nil
end

-- Function to check if a name is an IP address
-- @param name The name to check
-- @return true if it's an IP address, false otherwise
local function is_ip(name)
  return string.match(name, "^%d+%.%d+%.%d+%.%d+$")
end

-- Function to check for IP addresses in certificate
-- @param cert The certificate object
-- @return true and alert message if IP found, false otherwise
local function contains_ip(cert)
  if cert.subject and cert.subject.commonName and 
     is_ip(cert.subject.commonName) then
    return true, string.format("Certificate common name is an IP address: %s", cert.subject.commonName)
  end

  if cert.extensions and cert.extensions.subjectAltName then
    for _, san in ipairs(cert.extensions.subjectAltName) do
      if is_ip(san) then
        return true, string.format("Certificate SAN contains an IP address: %s", san)
      end 
    end
  end

  return false, nil
end

-- Function to validate certificate type and key size
-- @param cert The certificate object
-- @return true if valid, false and reason otherwise
local function valid_certificate_type(cert)
  if cert.pubkey then
    local key_type, key_bits = string.lower(cert.pubkey.type), cert.pubkey.bits
    if key_type == "rsa" and key_bits < 2048 then
      return false, string.format("Weak RSA key size (minimum 2048 required): %d bits", key_bits)
    elseif key_type == "ec" then
      if cert.pubkey.pem and not string.lower(cert.pubkey.pem):match("prime256v1") then
        return false, string.format("Weak EC key type (prime256v1 required): %s", cert.pubkey.pem)
      end
    end
    return true, nil
  end
end


-- Function to check for self-signed certificate
-- @param cert The certificate object
-- @return true if self-signed, false otherwise
local function is_self_signed(cert)
  if cert.issuer.commonName and cert.subject.commonName then
    return string.lower(cert.issuer.commonName) == string.lower(cert.subject.commonName)
  end
end

-- Function to check adequate certificate lifespan between 99 and 366 days
-- @param cert The certificate object
-- @return true if adequate, false otherwise
local function get_cert_lifespan_in_days(cert)
    if not cert.validity or not cert.validity.notAfter or not cert.validity.notBefore then
        stdnse.debug(1, " *** Debugging: Missing certificate validity data")
        return -1
    end
    stdnse.debug(1, " *** Debugging: Not before lifespan: %d", cert.validity.notBefore.day)
    stdnse.debug(1, " *** Debugging: Not after lifespan: %d", cert.validity.notAfter.sec)
 
    local_not_before_ts = os.time({
      year=cert.validity.notBefore.year,
      month=cert.validity.notBefore.month,
      day=cert.validity.notBefore.day,
      hour=cert.validity.notBefore.hour,
      min=cert.validity.notBefore.min,
      sec=cert.validity.notBefore.sec,
    })

    local_not_after_ts = os.time({
      year=cert.validity.notAfter.year,
      month=cert.validity.notAfter.month,
      day=cert.validity.notAfter.day,
      hour=cert.validity.notAfter.hour,
      min=cert.validity.notAfter.min,
      sec=cert.validity.notAfter.sec,
    })

    stdnse.debug(1, " *** Debugging: Not before lifespan ts: %d", local_not_before_ts)
    stdnse.debug(1, " *** Debugging: Not after lifespan ts: %d", local_not_after_ts)

    if local_not_after_ts < local_not_before_ts then
      stdnse.debug(1, " *** Debugging: The after date was lower than the before date")
      return -1
    end

    local lifespan_days = (local_not_after_ts-local_not_before_ts)/ (24*60*60)

    stdnse.debug(1, " *** Debugging: The lifespan in days is: %d", lifespan_days)

    return lifespan_days
    
end

-- Function to check domain name matching
-- @param host_name The host name to check
-- @param cert The certificate object
-- @return true if matches, false and reason otherwise
local function domain_name_matching(host_name,cert)
  if not host_name or host_name == "" then
    return false, string.format("Domain Name Matching: Host name is empty or nil")
  end
  if host_name ~= cert.subject.commonName then
    return false, string.format("Domain Name Matching: Host name %s does not match certificate CN %s", host_name, cert.subject.commonName)
  end
  if cert.extensions and cert.extensions.subjectAltName then
    local san_match = false
    for _, san in ipairs(cert.extensions.subjectAltName) do
      if host_name == san then
        san_match = true
        break
      end
    end
    if not san_match then
      return false, string.format("Domain Name Matching: Host name %s does not match any certificate SAN", host_name)
    end
  end
  return true, nil
end

local function format_alerts(alerts_table)
  local result = {}
  local severity_levels = {
    { key = "critical", name = "CRITICAL", debug = " *** Debugging: No critical alerts detected ***********" },
    { key = "high", name = "HIGH", debug = " *** Debugging: No high alerts detected ***********" },
    { key = "medium", name = "MEDIUM", debug = " *** Debugging: No medium alerts detected ***********" },
    { key = "low", name = "LOW", debug = " *** Debugging: No low alerts detected ***********" }
  }
  
  local separator = "**********************"
  
  for _, level in ipairs(severity_levels) do
    local alerts = alerts_table[level.key]
    if #alerts > 0 then
      table.insert(result, "\n")
      table.insert(result, separator)
      table.insert(result, string.format("%s ALERTS: %d", level.name, #alerts))
      table.insert(result, separator)
      for _, alert in ipairs(alerts) do
        table.insert(result, "- " .. alert)
      end
      table.insert(result, "\n")
    else
      stdnse.debug(1, level.debug)
    end
  end
  
  return result
end

-- Function to check the hsts header setting
-- @param host_name The host name to check
-- @param cert The certificate object
-- @return the header if exists and nil if not
local function hsts_header(host, port, path)
  if http_response and http_response.header and http_response.header['strict-transport-security'] then
    stdnse.debug(1, " *** Debugging: Header: Strict-Transport-Security: %s, Status: %s", http_response.header['strict-transport-security'])
    return http_response.header['strict-transport-security']
  elseif shortport.ssl(host,port) then
    stdnse.debug(1, " *** Debugging:  HSTS not configured in HTTPS Server ***********")
    return nil
  end

end


-- https://nmap.org/nsedoc/lib/sslcert.html
action = function(host, port)

  -- 1. Obtain certificate information

  local status, cert = sslcert.getCertificate(host, port)

  stdnse.debug(1, " *** Debugging:  The status of the certificte is %s ***********", status)

  if not status then
    return stdnse.format_output(false, "Failed to retrieve certificate")
  end

 -- 2. Obtain TLS information
  local tls_response = get_TLS_info(host, port)

  if not tls_response then
    return stdnse.format_output(false, "Failed to retrieve TLS information")
  end

  local protocol, cipher, compressor = nil, nil, nil
  protocol, cipher, compressor = tls_response.protocol, tls_response.cipher, tls_response.compressor

  
  if not protocol or not cipher then
    return stdnse.format_output(false, "Incomplete TLS information")
  end


-- 3. Alerts

-- ====================================
-- 3. 1          CRITICAL ALERTS
-- ====================================

-- CBC mode or SHA hash algorithm on TLS cipher
if has_cbc_or_sha(cipher) then
  table.insert(alerts.critical, string.format("Cipher includes CBC mode or SHA hash algorithm: %s", cipher))
end

-- Verify if the compression is enabled on TLS
if compressor and compressor ~= 0 then
  table.insert(alerts.critical, "TLS compression is enabled")
end

-- Alert on self-signed certificate
if is_self_signed(cert) then
  table.insert(alerts.critical, "Self-signed certificate detected")
end

-- ====================================
-- 3. 2          HIGH ALERTS
-- ====================================

-- Supported protocols
if not string.find(protocol, "TLSv1.2") and not string.find(protocol, "TLSv1.3") then
  table.insert(alerts.high, string.format("Server does not support TLS 1.2 or TLS 1.3: %s", protocol))
end

-- Recommended cipher suites
if not is_cipher_recommended(cipher) then
  table.insert(alerts.high, string.format("Unsupported TLS cipher: %s", cipher))
end

-- Valid certificate public key type and size
local valid_type, reason = valid_certificate_type(cert)
if not valid_type then
  table.insert(alerts.high, reason)
end

-- ====================================
-- 3. 3         MEDIUM ALERTS
-- ====================================

-- Adequate certificate lifespan

local cert_lifespan=get_cert_lifespan_in_days(cert)

if cert_lifespan == -1 then
  table.insert(alerts.medium, string.format(
    "Certificate has an invalid lifespan."
  ))
elseif  cert_lifespan < 90 or cert_lifespan > 366 then
  table.insert(alerts.medium, string.format(
    "Certificates lifespan should range from 90 to 366 days: Current certificate lifespan is %d.", cert_lifespan
  ))
end

-- Domain matching

local domain_match, reason = domain_name_matching(host.targetname, cert)
if not domain_match then
  table.insert(alerts.medium, reason)
end

-- ====================================
-- 3. 4         LOW ALERTS
-- ====================================

-- Avoid non-qualified host names in certificate
local non_qualified, alert_msg = is_non_qualified_host(cert)
if non_qualified then
  table.insert(alerts.low, alert_msg)
end

-- Avoid IP addresses in certificate
local has_ip, alert_msg = contains_ip(cert)
if has_ip then
  table.insert(alerts.low, alert_msg)
end

-- ====================================
-- 3. 5         ENHANCED FUNCTIONALITY ALERTS (belong to previous categories)
-- ====================================

-- HSTS Header Check http-security-headers.nse
local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"

http_response = http.head(host, port, path)

if http_response == nil then
    stdnse.debug(1, " ***Debugging: Request failed ***********", status)
end

if http_response.header == nil then
    stdnse.debug(1, " *** Debugging:  Response didn't include a proper header ***********", status)
end

local header_hsts = hsts_header(host, port, path)

if header_hsts ~= nil then
  local max_age_str = string.match(header_hsts, "max%-age=%s*(%d+)")
    if max_age_str then
        local max_age = tonumber(max_age_str)
        if max_age < 63072000 then
            table.insert(alerts.medium, string.format("HSTS max-age is less than 2 year: %d seconds", max_age))
        end
    end
else
  table.insert(alerts.high, "HSTS header is not set in HTTPS server")
end

-- Server Information Disclosure
-- TO DO

-- TLS Curves
-- TO DO

-- DH Parameter Size
-- TO DO

-- Wildcard Certificate Scope
-- TO DO

-- CN and SAN Attributes
-- TO DO

-- Cipher Preference
-- TO DO



--4 Output formatting

  local result = format_alerts(alerts)
  return stdnse.format_output(true, result)

end