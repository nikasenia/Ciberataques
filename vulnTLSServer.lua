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

local have_ssl, openssl = pcall(require,'openssl')
local CHUNK_SIZE = 64

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
      stdnse.debug(1, " *** Debugging:  Failed to connect: %s ***********", sock)
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
    stdnse.debug(1, " *** Debugging:  Empty Server Response: %s ***********", response)
    return nil
  end

  -- Now let's parse the response to extract TLS info
  local i, record = tls.record_read(response, 1)
  if not record or record.type ~= "handshake" then
    stdnse.debug(1, " *** Debugging:  Error with TLS Response record.type: %s ***********", record.type)
    for k,v in pairs(record.body[1]) do
      stdnse.debug(1, " *** Debugging:  record key: %s | record value: %s ***********", k, v)
    end
    return nil
  end

  if record.body[1].type == "server_hello" then
    return record.body[1]
  end

  stdnse.debug(1, " *** Debugging:  Empty TLS Handshake Response: %s ***********", record)
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
-- @return the list of IP addresses found in CN or SAN
local function contains_ip(cert)
  local ip_findings = {}

  if cert.subject and cert.subject.commonName and is_ip(cert.subject.commonName) then
    table.insert(ip_findings, cert.subject.commonName)
  end

  if cert.extensions and cert.extensions.subjectAltName then
    for _, san in ipairs(cert.extensions.subjectAltName) do
      if is_ip(san) then
        table.insert(ip_findings, san)
      end 
    end
  end

  return ip_findings
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

    local_not_after_ts = os.time({
      year=cert.validity.notAfter.year,
      month=cert.validity.notAfter.month,
      day=cert.validity.notAfter.day,
      hour=cert.validity.notAfter.hour,
      min=cert.validity.notAfter.min,
      sec=cert.validity.notAfter.sec,
    })

    stdnse.debug(1, " *** Debugging: Not after lifespan ts: %d", local_not_after_ts)


    local lifespan_days = math.floor((local_not_after_ts - os.time()) / (24 * 60 * 60))

    stdnse.debug(1, " *** Debugging: The days left to expire are : %f", lifespan_days)

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
    return http_response.header['strict-transport-security']
  elseif shortport.ssl(host,port) then
    stdnse.debug(1, " *** Debugging:  HSTS not configured in HTTPS Server ***********")
    return nil
  end

end

-- Function to check for server information disclosure in HTTP headers
-- @param http_response The HTTP response object
-- @return table with alerts if version information found
local function check_server_info_disclosure(http_response)
  local server_alerts = {}
  
  if not http_response or not http_response.header then
    return server_alerts
  end

  -- Common headers that may contain version information
  local version_headers = {
    "server",
    "x-powered-by", 
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-runtime",
    "x-version"
  }

  -- Patterns to detect version numbers
  local version_patterns = {
    "%d+%.%d+",        -- Basic version pattern (X.X)
    "%d+%.%d+%.%d+",   -- Three-part version (X.X.X)
    "%d+%.%d+%.%d+%.%d+", -- Four-part version (X.X.X.X)
    "v%d+",            -- vX format
    "version%s+%d+"    -- "version X" format
  }

  for _, header_name in ipairs(version_headers) do
    local header_value = http_response.header[header_name]
    if header_value then
      stdnse.debug(1, " *** Debugging: Found %s header: %s", header_name, header_value)
      
      -- Check if header contains version numbers
      for _, pattern in ipairs(version_patterns) do
        local version_match = string.match(string.lower(header_value), pattern)
        if version_match then
          table.insert(server_alerts, {
            header = header_name,
            value = header_value,
            version = version_match
          })
          break  -- Found a version in this header, move to next header
        end
      end
    end
  end

  return server_alerts
end

-- Function to check if wildcards are included in domains
-- @param cert The certificate object
-- @param alerts The alerts table to store findings
-- @return list of domains which used wildcards
local function wildcard_included(cert, alerts)
  local wildcard_findings = {}
  
  if cert.subject.commonName and string.find(cert.subject.commonName, "%*") then
    table.insert(wildcard_findings, cert.subject.commonName)
  end
  
  -- check SAN for wildcards
  if cert.extensions and cert.extensions.subjectAltName then
    for _, san in ipairs(cert.extensions.subjectAltName) do
      if string.find(san, "%*") then
        table.insert(wildcard_findings, san)
      end
    end
  end
  return wildcard_findings
end

-- Function to check domain name matching
-- @param host_name The host name to check
-- @param cert The certificate object
-- @return true if CN exists and present in SAN, false and reason otherwise
local function cn_and_san_compatibility(cert)
  local cn = cert.subject.commonName
  if not cn then
    return false, string.format("CN and SAN Attributes: Common Name is empty or nil.")
  end


  if cert.extensions and cert.extensions.subjectAltName then
    for _, san in ipairs(cert.extensions.subjectAltName) do
      if cn == san then
        return true, nil
      end
    end
  end

  return false, string.format("CN and SAN Attributes: CN %s is not included in the SAN.", cn)
  
end

-- Down here is from the ssl-enum-ciphers script ----------------------------------------------------------------
local function ctx_log(level, protocol, fmt, ...)
  return stdnse.debug(level, "(%s) " .. fmt, protocol, ...)
end

-- returns a function that yields a new tls record each time it is called
local function get_record_iter(sock)
  local buffer = ""
  local i = 1
  local fragment
  return function ()
    local record
    i, record = tls.record_read(buffer, i, fragment)
    if record == nil then
      local status, err
      status, buffer, err = tls.record_buffer(sock, buffer, i)
      if not status then
        return nil, err
      end
      i, record = tls.record_read(buffer, i, fragment)
      if record == nil then
        return nil, "done"
      end
    end
    fragment = record.fragment
    return record
  end
end

local function sorted_keys(t)
  local ret = {}
  for k, _ in pairs(t) do
    ret[#ret+1] = k
  end
  table.sort(ret)
  return ret
end

local function in_chunks(t, size)
  size = math.floor(size)
  if size < 1 then size = 1 end
  local ret = {}
  for i = 1, #t, size do
    local chunk = {}
    for j = i, i + size - 1 do
      chunk[#chunk+1] = t[j]
    end
    ret[#ret+1] = chunk
  end
  return ret
end

local function try_params(host, port, t)

  -- Use Nmap's own discovered timeout plus 5 seconds for host processing
  -- Default to 10 seconds total.
  local timeout = ((host.times and host.times.timeout) or 5) * 1000 + 5000

  -- Create socket.
  local status, sock, err
  local specialized = sslcert.getPrepareTLSWithoutReconnect(port)
  if specialized then
    status, sock = specialized(host, port)
    if not status then
      ctx_log(1, t.protocol, "Can't connect: %s", sock)
      return nil
    end
  else
    sock = nmap.new_socket()
    sock:set_timeout(timeout)
    status, err = sock:connect(host, port)
    if not status then
      ctx_log(1, t.protocol, "Can't connect: %s", err)
      sock:close()
      return nil
    end
  end

  sock:set_timeout(timeout)

  -- Send request.
  local req = tls.client_hello(t)
  status, err = sock:send(req)
  if not status then
    ctx_log(1, t.protocol, "Can't send: %s", err)
    sock:close()
    return nil
  end

  -- Read response.
  local get_next_record = get_record_iter(sock)
  local records = {}
  while true do
    local record
    record, err = get_next_record()
    if not record then
      ctx_log(1, t.protocol, "Couldn't read a TLS record: %s", err)
      sock:close()
      return records
    end
    -- Collect message bodies into one record per type
    records[record.type] = records[record.type] or record
    local done = false
    for j = 1, #record.body do -- no ipairs because we append below
      local b = record.body[j]
      done = ((record.type == "alert" and b.level == "fatal") or
        (record.type == "handshake" and b.type == "server_hello_done"))
      table.insert(records[record.type].body, b)
    end
    if done then
      sock:close()
      return records
    end
  end
end

-- Get TLS extensions
local function base_extensions(host)
  local tlsname = tls.servername(host)
  return {
    -- Claim to support common elliptic curves
    ["elliptic_curves"] = tls.EXTENSION_HELPERS["elliptic_curves"](tls.DEFAULT_ELLIPTIC_CURVES),
    -- Enable SNI if a server name is available
    ["server_name"] = tlsname and tls.EXTENSION_HELPERS["server_name"](tlsname),
  }
end

-- Get a message body from a record which has the specified property set to value
local function get_body(record, property, value)
  for i, b in ipairs(record.body) do
    if b[property] == value then
      return b
    end
  end
  return nil
end

local function remove(t, e)
  for i, v in ipairs(t) do
    if v == e then
      table.remove(t, i)
      return i
    end
  end
  return nil
end


local function letter_grade (score)
  if not tonumber(score) then return "unknown" end
  if score >= 0.80 then
    return "A"
  elseif score >= 0.65 then
    return "B"
  elseif score >= 0.50 then
    return "C"
  elseif score >= 0.35 then
    return "D"
  elseif score >= 0.20 then
    return "E"
  else
    return "F"
  end
end


-- Offer two ciphers and return the one chosen by the server. Returns nil and
-- an error message in case of a server error.
local function compare_ciphers(host, port, protocol, cipher_a, cipher_b)
  local t = {
    ["protocol"] = protocol,
    ["ciphers"] = {cipher_a, cipher_b},
    ["extensions"] = base_extensions(host),
  }
  local records = try_params(host, port, t)
  local server_hello = records.handshake and get_body(records.handshake, "type", "server_hello")
  if server_hello then
    ctx_log(2, protocol, "compare %s %s -> %s", cipher_a, cipher_b, server_hello.cipher)
    return server_hello.cipher
  else
    ctx_log(2, protocol, "compare %s %s -> error", cipher_a, cipher_b)
    return nil, string.format("Error when comparing %s and %s", cipher_a, cipher_b)
  end
end

-- Try to find whether the server prefers its own ciphersuite order or that of
-- the client.
--
-- The return value is (preference, err). preference is a string:
--   "server": the server prefers its own order. In this case ciphers is non-nil.
--   "client": the server follows the client preference. ciphers is nil.
--   "indeterminate": returned when there are only 0 or 1 ciphers. ciphers is nil.
--   nil: an error occurred during the test. err is non-nil.
-- err is an error message string that is non-nil when preference is nil or
-- indeterminate.
--
-- The algorithm tries offering two ciphersuites in two different orders. If
-- the server makes a different choice each time, "client" preference is
-- assumed. Otherwise, "server" preference is assumed.
local function find_cipher_preference(host, port, protocol, ciphers)
  -- Too few ciphers to make a decision?
  if #ciphers < 2 then
    return "indeterminate", "Too few ciphers supported"
  end

  -- Do a comparison in both directions to see if server ordering is consistent.
  local cipher_a, cipher_b = ciphers[1], ciphers[2]
  ctx_log(1, protocol, "Comparing %s to %s", cipher_a, cipher_b)
  local winner_forwards, err = compare_ciphers(host, port, protocol, cipher_a, cipher_b)
  if not winner_forwards then
    return nil, err
  end
  local winner_backward, err = compare_ciphers(host, port, protocol, cipher_b, cipher_a)
  if not winner_backward then
    return nil, err
  end
  if winner_forwards ~= winner_backward then
    return "client", nil
  end
  return "server", nil
end

-- Score a ciphersuite implementation (including key exchange info)
local function score_cipher (kex_strength, cipher_info)
  local kex_score, cipher_score
  if not kex_strength or not cipher_info.size then
    return "unknown"
  end
  if kex_strength == 0 then
    return 0
  elseif kex_strength < 512 then
    kex_score = 0.2
  elseif kex_strength < 1024 then
    kex_score = 0.4
  elseif kex_strength < 2048 then
    kex_score = 0.8
  elseif kex_strength < 4096 then
    kex_score = 0.9
  else
    kex_score = 1.0
  end

  if cipher_info.size == 0 then
    return 0
  elseif cipher_info.size < 128 then
    cipher_score = 0.2
  elseif cipher_info.size < 256 then
    cipher_score = 0.8
  else
    cipher_score = 1.0
  end

  -- Based on SSL Labs' 30-30-40 rating without the first 30% (protocol support)
  return 0.43 * kex_score + 0.57 * cipher_score
end

local function remove_high_byte_ciphers(t)
  local output = {}
  for i, v in ipairs(t) do
    if tls.CIPHERS[v] <= 255 then
      output[#output+1] = v
    end
  end
  return output
end

-- Find which ciphers out of group are supported by the server.
local function find_ciphers_group(host, port, protocol, group, scores)
  local results = {}
  local t = {
    ["protocol"] = protocol,
    ["record_protocol"] = protocol, -- improve chances of immediate rejection
    ["extensions"] = base_extensions(host),
  }

  -- This is a hacky sort of tristate variable. There are three conditions:
  -- 1. false = either ciphers or protocol is bad. Keep trying with new ciphers
  -- 2. nil = The protocol is bad. Abandon thread.
  -- 3. true = Protocol works, at least some cipher must be supported.
  local protocol_worked = false
  while (next(group)) do
    t["ciphers"] = group

    local records = try_params(host, port, t)
    if not records then
      return nil
    end
    local handshake = records.handshake

    if handshake == nil then
      local alert = records.alert
      if alert then
        ctx_log(2, protocol, "Got alert: %s", alert.body[1].description)
        if alert["protocol"] ~= protocol then
          ctx_log(1, protocol, "Protocol mismatch (received %s)", alert.protocol)
          -- Sometimes this is not an actual rejection of the protocol. Check specifically:
          if get_body(alert, "description", "protocol_version") then
            protocol_worked = nil
          end
          break
        elseif get_body(alert, "description", "handshake_failure") then
          protocol_worked = true
          ctx_log(2, protocol, "%d ciphers rejected.", #group)
          break
        end
      elseif protocol_worked then
        ctx_log(2, protocol, "%d ciphers rejected. (No handshake)", #group)
      else
        ctx_log(1, protocol, "%d ciphers and/or protocol rejected. (No handshake)", #group)
      end
      break
    else
      local server_hello = get_body(handshake, "type", "server_hello")
      if not server_hello then
        ctx_log(2, protocol, "Unexpected record received.")
        break
      end
      if server_hello.protocol ~= protocol then
        ctx_log(1, protocol, "Protocol rejected. cipher: %s", server_hello.cipher)
        -- Some implementations will do this if a cipher is supported in some
        -- other protocol version but not this one. Gotta keep trying.
        if not remove(group, server_hello.cipher) then
          -- But if we didn't even offer this cipher, then give up. Crazy!
          protocol_worked = protocol_worked or nil
        end
        break
      else
        protocol_worked = true
        local name = server_hello.cipher
        ctx_log(2, protocol, "Cipher %s chosen.", name)
        if not remove(group, name) then
          ctx_log(1, protocol, "chose cipher %s that was not offered.", name)
          ctx_log(1, protocol, "removing high-byte ciphers and trying again.")
          local size_before = #group
          group = remove_high_byte_ciphers(group)
          ctx_log(1, protocol, "removed %d high-byte ciphers.", size_before - #group)
          if #group == size_before then
            -- No changes... Server just doesn't like our offered ciphers.
            break
          end
        else
          -- Add cipher to the list of accepted ciphers.
          table.insert(results, name)
          if scores then
            local info = tls.cipher_info(name)
            -- Some warnings:
            if info.hash and info.hash == "MD5" then
              scores.warnings["Ciphersuite uses MD5 for message integrity"] = true
            end
            if info.mode and info.mode == "CBC" and info.block_size <= 64 then
              scores.warnings[("64-bit block cipher %s vulnerable to SWEET32 attack"):format(info.cipher)] = true
            end
            if protocol == "SSLv3" and  info.mode and info.mode == "CBC" then
              scores.warnings["CBC-mode cipher in SSLv3 (CVE-2014-3566)"] = true
            elseif info.cipher == "RC4" then
              scores.warnings["Broken cipher RC4 is deprecated by RFC 7465"] = true
            end
            local kex = tls.KEX_ALGORITHMS[info.kex]
            scores.any_pfs_ciphers = kex.pfs or scores.any_pfs_ciphers
            local extra, kex_strength
            if kex.anon then
              kex_strength = 0
            elseif kex.export then
              if info.kex:find("1024$") then
                kex_strength = 1024
              else
                kex_strength = 512
              end
            else
              if have_ssl and kex.pubkey then
                local certs = get_body(handshake, "type", "certificate")
                -- Assume RFC compliance:
                -- "The sender's certificate MUST come first in the list."
                -- This may not always be the case, so
                -- TODO: reorder certificates and validate entire chain
                -- TODO: certificate validation (date, self-signed, etc)
                local c, err
                if certs == nil then
                  err = "no certificate message"
                else
                   c, err = sslcert.parse_ssl_certificate(certs.certificates[1])
                end
                if not c then
                  stdnse.debug1("Failed to parse certificate: %s", err)
                elseif c.pubkey.type == kex.pubkey then
                  local sigalg = c.sig_algorithm:match("([mM][dD][245])")
                  if sigalg then
                    -- MD2 and MD5 are broken
                    kex_strength = 0
                    scores.warnings["Insecure certificate signature: " .. string.upper(sigalg)] = true
                  else
                    sigalg = c.sig_algorithm:match("([sS][hH][aA]1)")
                    if sigalg then
                      -- TODO: Update this when SHA-1 is fully deprecated in 2017
                      if type(c.notBefore) == "table" and c.notBefore.year >= 2016 then
                        kex_strength = 0
                        scores.warnings["Deprecated SHA1 signature in certificate issued after January 1, 2016"] = true
                      end
                      scores.warnings["Weak certificate signature: SHA1"] = true
                    end
                    kex_strength = tls.rsa_equiv(kex.pubkey, c.pubkey.bits)
                    if c.pubkey.exponent then
                      if openssl.bignum_bn2dec(c.pubkey.exponent) == "1" then
                        kex_strength = 0
                        scores.warnings["Certificate RSA exponent is 1, score capped at F"] = true
                      end
                    end
                    if c.pubkey.ecdhparams then
                      if c.pubkey.ecdhparams.curve_params.ec_curve_type == "namedcurve" then
                        extra = c.pubkey.ecdhparams.curve_params.curve
                      else
                        extra = string.format("%s %d", c.pubkey.ecdhparams.curve_params.ec_curve_type, c.pubkey.bits)
                      end
                    else
                      extra = string.format("%s %d", kex.pubkey, c.pubkey.bits)
                    end
                  end
                end
              end
              local ske = get_body(handshake, "type", "server_key_exchange")
              if kex.server_key_exchange and ske then
                local kex_info = kex.server_key_exchange(ske.data, protocol)
                if kex_info.strength then
                  local rsa_bits = tls.rsa_equiv(kex.type, kex_info.strength)
                  local low_strength_warning = false
                  if kex_strength and kex_strength > rsa_bits then
                    kex_strength = rsa_bits
                    low_strength_warning = true
                  end
                  kex_strength = kex_strength or rsa_bits
                  if kex_info.ecdhparams then
                    if kex_info.ecdhparams.curve_params.ec_curve_type == "namedcurve" then
                      extra = kex_info.ecdhparams.curve_params.curve
                    else
                      extra = string.format("%s %d", kex_info.ecdhparams.curve_params.ec_curve_type, kex_info.strength)
                    end
                  else
                    extra = string.format("%s %d", kex.type, kex_info.strength)
                  end
                  if low_strength_warning then
                    scores.warnings[(
                        "Key exchange (%s) of lower strength than certificate key"
                      ):format(extra)] = true
                  end
                end
                if kex_info.rsa and kex_info.rsa.exponent == 1 then
                  kex_strength = 0
                  scores.warnings["Certificate RSA exponent is 1, score capped at F"] = true
                end
              end
            end
            scores[name] = {
              cipher_strength=info.size,
              kex_strength = kex_strength,
              extra = extra,
              letter_grade = letter_grade(score_cipher(kex_strength, info))
            }
          end
        end
      end
    end
  end
  return results, protocol_worked
end

local function get_chunk_size(host, protocol)
  -- Try to make sure we don't send too big of a handshake
  -- https://github.com/ssllabs/research/wiki/Long-Handshake-Intolerance
  local len_t = {
    protocol = protocol,
    ciphers = {},
    extensions = base_extensions(host),
  }
  local cipher_len_remaining = 255 - #tls.client_hello(len_t)
  -- if we're over 255 anyway, just go for it.
  -- Each cipher adds 2 bytes
  local max_chunks = cipher_len_remaining > 1 and cipher_len_remaining // 2 or CHUNK_SIZE
  -- otherwise, use the min
  return max_chunks < CHUNK_SIZE and max_chunks or CHUNK_SIZE
end



-- Break the cipher list into chunks of CHUNK_SIZE (for servers that can't
-- handle many client ciphers at once), and then call find_ciphers_group on
-- each chunk.
local function find_ciphers(host, port, protocol)

  local ciphers = in_chunks(sorted_keys(tls.CIPHERS), get_chunk_size(host, protocol))

  local results = {}
  local scores = {warnings={}}
  -- Try every cipher.
  for _, group in ipairs(ciphers) do
    local chunk, protocol_worked = find_ciphers_group(host, port, protocol, group, scores)
    if protocol_worked == nil then return nil end
    for _, name in ipairs(chunk) do
      table.insert(results, name)
    end
  end
  if not next(results) then return nil end
  scores.warnings["Forward Secrecy not supported by any cipher"] = (not scores.any_pfs_ciphers) or nil
  scores.any_pfs_ciphers = nil

  return results, scores
end


-- End of the ssl-enum-ciphers script ----------------------------------------------------------------




-- https://nmap.org/nsedoc/lib/sslcert.html
action = function(host, port)

  stdnse.debug(1, " *** Debugging:  STARTING PROCESS ***********")


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
elseif cert_lifespan < 90 then
  table.insert(alerts.medium, string.format(
    "Certificate lifespan is %d days (less than recommended 90 days)", cert_lifespan
  ))
elseif  cert_lifespan > 366 then
  table.insert(alerts.medium, string.format(
    "Certificate lifespan is %d days (more than recommended 366 days)", cert_lifespan
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
local ip_findings = contains_ip(cert)
if #ip_findings > 0 then
    local alert_message = "Certificate contains IP addresses in CN or SAN: " .. table.concat(ip_findings, ", ")
    table.insert(alerts.low, alert_message)
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
local server_info_alerts = check_server_info_disclosure(http_response)
if #server_info_alerts > 0 then
  for _, alert in ipairs(server_info_alerts) do
    table.insert(alerts.medium, string.format(
      "Server information disclosure in %s header: %s (version: %s)", 
      alert.header, alert.value, alert.version
    ))
  end
end

-- TLS Curves
-- TO DO

-- DH Parameter Size
-- TO DO

-- Wildcard Certificate Scope
local wildcard_findings = wildcard_included(cert, alerts)
if #wildcard_findings > 0 then
    local alert_message = "Wildcard certificate scope: The following domains in CN or SAN use wildcards: " .. table.concat(wildcard_findings, ", ")
    table.insert(alerts.low, alert_message)
end

-- CN and SAN Attributes
local cn_and_san_compatible, reason = cn_and_san_compatibility(cert)
if not cn_and_san_compatible then
  table.insert(alerts.low, reason)
end 

-- Cipher Preference
local ciphers = find_ciphers(host, port, protocol)
local entity, err = find_cipher_preference(host, port, protocol, ciphers)
if not entity then
  stdnse.debug(1, " *** Debugging:  Could not determine cipher preference: %s ***********", err)
elseif entity == "client" then
  table.insert(alerts.low, "Server follows client cipher preference")
end

--4 Output formatting

  local result = format_alerts(alerts)
  return stdnse.format_output(true, result)

end