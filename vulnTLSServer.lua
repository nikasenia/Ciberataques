
-- vulnTLSServer.nse
-- NSE script to detect vulnerabilities in TLS/SSL servers
-- Cyber Attack Techniques Laboratory

description = [[
This script analyzes vulnerabilities in TLS/SSL servers.
It detects obsolete protocol versions, weak ciphers, and other common security vulnerabilities.
Note: TLS 1.3 checks are not performed as tls.lua library doesn't support it.
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

-- Libraries
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local sslcert = require "sslcert"
local tls = require "tls"
local http = require "http"

-- Metadata
author = "TO DO"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe", "discovery"}
portrule = shortport.ssl

-- Constants
local have_ssl, openssl = pcall(require,'openssl')
local CHUNK_SIZE = 64

-- Alert storage
local alerts = {
  critical = {},
  high = {},
  medium = {},
  low = {}
}

-- Mozilla's Intermediate recommended cipher suites
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
-- ====================================
--        Helper Functions
-- ====================================

-- ====================================
--     Cipher Validation Functions
-- ====================================

-- Check if cipher is in recommended list
local function is_cipher_recommended(cipher_name)
  if not cipher_name then return false end
  for _, rec_cipher in ipairs(recommended_ciphers) do
    if cipher_name == rec_cipher then return true end
  end
  return false
end

-- Check if cipher uses CBC mode or SHA-1 hash algorithm
local function has_cbc_or_sha(cipher_name)
  if not cipher_name then return false end
  local upper = string.upper(cipher_name)
  return string.find(upper, "CBC") or 
         string.find(upper, "SHA1") or 
         string.find(upper, "SHA%-1") or
         string.find(upper, "_SHA$") or 
         string.find(upper, "_SHA_")
end

-- ====================================
--  Certificate Parsing Functions
-- ====================================

-- Extract Subject Alternative Names from certificate
local function get_SAN(cert)
  local san_list = {}
  if not cert.extensions then return san_list end
  
  for k, v in pairs(cert.extensions) do
    if type(v) == "table" then
      for k2, v2 in pairs(v) do
        if k2 == "name" and string.find(v2, "Subject Alternative Name") then
          if v.value then
            for san_entry in string.gmatch(v.value, "([^,]+)") do
              san_entry = san_entry:match("^%s*(.-)%s*$")
              if san_entry ~= "" then
                table.insert(san_list, san_entry)
              end
            end
          end
          return san_list
        end
      end
    end
  end
  return san_list
end

-- Check if a name is an IP address
local function is_ip(name)
  return string.match(name, "^%d+%.%d+%.%d+%.%d+$")
end

-- Extract domain value from SAN entry (removes DNS: or IP: prefix)
local function extract_san_value(san)
  return san:match("^DNS:(.+)") or san:match("^IP:(.+)") or san
end

-- Check for non-qualified hostnames in certificate
local function get_non_qualified_hosts(cert)
  local findings = {}
  if cert.subject.commonName and not string.find(cert.subject.commonName, "%.") then
    table.insert(findings, cert.subject.commonName)
  end
  
  for _, san in ipairs(get_SAN(cert)) do
    local domain = extract_san_value(san)
    if not string.find(domain, "%.") then
      table.insert(findings, domain)
    end
  end
  return findings
end

-- Check for IP addresses in certificate
local function get_ip_addresses(cert)
  local findings = {}
  if cert.subject and cert.subject.commonName and is_ip(cert.subject.commonName) then
    table.insert(findings, cert.subject.commonName)
  end
  
  for _, san in ipairs(get_SAN(cert)) do
    local value = extract_san_value(san)
    if is_ip(value) then
      table.insert(findings, value)
    end
  end
  return findings
end

-- ====================================
--  Certificate Validation Functions
-- ====================================

-- Validate certificate key type and size
local function validate_certificate_key(cert)
  if not cert.pubkey then return true, nil end
  
  local key_type = string.lower(cert.pubkey.type)
  local key_bits = cert.pubkey.bits
  
  if key_type == "rsa" and key_bits < 2048 then
    return false, string.format("Weak RSA key size (minimum 2048 required): %d bits", key_bits)
  elseif key_type == "ec" and cert.pubkey.pem then
    if not string.lower(cert.pubkey.pem):match("prime256v1") then
      return false, string.format("Weak EC key type (prime256v1 required): %s", cert.pubkey.pem)
    end
  end
  return true, nil
end

-- Check if certificate is self-signed
local function is_self_signed(cert)
  return cert.issuer.commonName and cert.subject.commonName and
         string.lower(cert.issuer.commonName) == string.lower(cert.subject.commonName)
end

-- Calculate certificate lifespan in days
local function get_cert_lifespan_days(cert)
  if not cert.validity or not cert.validity.notAfter or not cert.validity.notBefore then
    stdnse.debug(1, "[DEBUG] Missing certificate validity data")
    return -1
  end
  
  local not_after_ts = os.time({
    year = cert.validity.notAfter.year,
    month = cert.validity.notAfter.month,
    day = cert.validity.notAfter.day,
    hour = cert.validity.notAfter.hour,
    min = cert.validity.notAfter.min,
    sec = cert.validity.notAfter.sec,
  })
  
  local lifespan_days = math.floor((not_after_ts - os.time()) / 86400)
  stdnse.debug(1, "[DEBUG] Certificate expires in %d days", lifespan_days)
  return lifespan_days
end

-- Check domain name matching
local function validate_domain_match(host_name, cert)
  if not host_name or host_name == "" then
    return false, "Domain Name Matching: Host name is empty or nil"
  end
  
  if host_name ~= cert.subject.commonName then
    return false, string.format("Domain Name Matching: Host name %s does not match CN %s", 
                                host_name, cert.subject.commonName)
  end
  
  local san_list = get_SAN(cert)
  if #san_list > 0 then
    for _, san in ipairs(san_list) do
      if host_name == extract_san_value(san) then
        return true, nil
      end
    end
    return false, string.format("Domain Name Matching: Host name %s not in SAN", host_name)
  end
  return true, nil
end

-- ====================================
--    Output Formatting Functions
-- ====================================

-- Format alerts for output
local function format_alerts(alerts_table)
  local result = {}
  local severity_levels = {
    {key = "critical", name = "CRITICAL"},
    {key = "high", name = "HIGH"},
    {key = "medium", name = "MEDIUM"},
    {key = "low", name = "LOW"}
  }
  
  for _, level in ipairs(severity_levels) do
    local alerts = alerts_table[level.key]
    if #alerts > 0 then
      table.insert(result, "\n**********************")
      table.insert(result, string.format("%s ALERTS: %d", level.name, #alerts))
      table.insert(result, "**********************")
      for _, alert in ipairs(alerts) do
        table.insert(result, "- " .. alert)
      end
      table.insert(result, "\n")
    else
      stdnse.debug(1, "[DEBUG] No %s alerts detected", string.lower(level.name))
    end
  end
  return result
end

-- ====================================
--   HTTP Header Analysis Functions
-- ====================================

-- Check for server information disclosure in HTTP headers
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
      stdnse.debug(1, "[DEBUG] Found %s header: %s", header_name, header_value)
      
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

-- ====================================
--   Enhanced Certificate Checks
-- ====================================

-- Check if wildcards are included in domains
local function get_wildcard_domains(cert)
  local findings = {}
  if cert.subject.commonName and string.find(cert.subject.commonName, "%*") then
    table.insert(findings, cert.subject.commonName)
  end
  
  for _, san in ipairs(get_SAN(cert)) do
    if string.find(san, "%*") then
      table.insert(findings, san)
    end
  end
  return findings
end

-- Check if CN exists and is present in SAN
local function validate_cn_san_compatibility(cert)
  local cn = cert.subject.commonName
  if not cn then
    return false, "[ENHANCED] CN and SAN Attributes: Common Name is empty or nil."
  end
 
  local san_list = get_SAN(cert)
  if #san_list == 0 then
    return false, "[ENHANCED] CN and SAN Attributes: No Subject Alternative Name extension found."
  end
  
  for _, san_entry in ipairs(san_list) do
    if extract_san_value(san_entry) == cn then
      stdnse.debug(1, "[DEBUG] CN matches SAN entry: %s", cn)
      return true, nil
    end
  end
  return false, string.format("[ENHANCED] CN and SAN Attributes: CN %s is not included in the SAN.", cn)
end

-- ====================================
--  TLS Protocol Analysis Functions
--  (Adapted from ssl-enum-ciphers)
-- ====================================

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

-- ====================================
--  TLS Connection & Handshake Functions
-- ====================================

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

-- ====================================
--   Cipher Suite Discovery Functions
-- ====================================

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
local function find_ciphers_group(host, port, protocol, group)
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
          -- But if we didn't even offer this cipher, then give up.
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
  -- Try every cipher.
  for _, group in ipairs(ciphers) do
    local chunk, protocol_worked = find_ciphers_group(host, port, protocol, group)
    if protocol_worked == nil then return nil end
    for _, name in ipairs(chunk) do
      table.insert(results, name)
    end
  end
  if not next(results) then return nil end

  return results
end

-- ====================================
--   Compression Detection Functions
-- ====================================

local function find_compressors(host, port, protocol, good_ciphers)
  local compressors = sorted_keys(tls.COMPRESSORS)
  local t = {
    ["protocol"] = protocol,
    ["ciphers"] = good_ciphers,
    ["extensions"] = base_extensions(host),
  }

  local results = {}

  -- Try every compressor.
  local protocol_worked = false
  while (next(compressors)) do
    -- Create structure.
    t["compressors"] = compressors

    -- Try connecting with compressor.
    local records = try_params(host, port, t)
    local handshake = records.handshake

    if handshake == nil then
      local alert = records.alert
      if alert then
        ctx_log(2, protocol, "Got alert: %s", alert.body[1].description)
        if alert["protocol"] ~= protocol then
          ctx_log(1, protocol, "Protocol rejected.")
          protocol_worked = nil
          break
        elseif get_body(alert, "description", "handshake_failure") then
          protocol_worked = true
          ctx_log(2, protocol, "%d compressors rejected.", #compressors)
          -- Should never get here, because NULL should be good enough.
          -- The server may just not be able to handle multiple compressors.
          if #compressors > 1 then -- Make extra-sure it's not crazily rejecting the NULL compressor
            compressors[1] = "NULL"
            for i = 2, #compressors, 1 do
              compressors[i] = nil
            end
            -- try again.
          else
            break
          end
        end
      elseif protocol_worked then
        ctx_log(2, protocol, "%d compressors rejected. (No handshake)", #compressors)
      else
        ctx_log(1, protocol, "%d compressors and/or protocol rejected. (No handshake)", #compressors)
      end
      break
    else
      local server_hello = get_body(handshake, "type", "server_hello")
      if not server_hello then
        ctx_log(2, protocol, "Unexpected record received.")
        break
      end
      if server_hello.protocol ~= protocol then
        ctx_log(1, protocol, "Protocol rejected.")
        protocol_worked = (protocol_worked == nil) and nil or false
        break
      else
        protocol_worked = true
        local name = server_hello.compressor
        ctx_log(2, protocol, "Compressor %s chosen.", name)
        remove(compressors, name)

        -- Add compressor to the list of accepted compressors.
        table.insert(results, name)
        if name == "NULL" then
          break -- NULL is always last choice, and must be included
        end
      end
    end
  end

  return results
end

-- ====================================
--         Main Action Function
-- ====================================

action = function(host, port)
  -- 1. Obtain certificate information
  local status, cert = sslcert.getCertificate(host, port)
  stdnse.debug(1, "[DEBUG] Certificate retrieval status: %s", status)

  if not status then
    return stdnse.format_output(false, "Failed to retrieve certificate")
  end

  -- 2. Test all TLS protocols and discover supported ciphers
  local all_supported_ciphers = {}
  local protocols_to_test = {"TLSv1.0", "TLSv1.1", "TLSv1.2"}
  
  for _, protocol in ipairs(protocols_to_test) do
    stdnse.debug(1, "[DEBUG] Testing protocol: %s", protocol)
    local supported_ciphers, warnings = find_ciphers(host, port, protocol)
    
    if supported_ciphers then
      all_supported_ciphers[protocol] = {
        ciphers = supported_ciphers,
        warnings = warnings
      }
      stdnse.debug(1, "[DEBUG] Found %d supported ciphers for %s", #supported_ciphers, protocol)
    else
      stdnse.debug(1, "[DEBUG] No supported ciphers found for %s", protocol)
    end
  end

  -- 3. Alerts

  -- ====================================
  -- 3.1 CRITICAL ALERTS
  -- ====================================

  -- Check for CBC mode or SHA hash algorithm in ALL supported ciphers
  local cbc_sha_found = false
  for _, data in pairs(all_supported_ciphers) do
    for _, cipher in ipairs(data.ciphers) do
      if has_cbc_or_sha(cipher) then
        table.insert(alerts.critical, string.format("Cipher includes CBC mode or SHA hash algorithm."))
        cbc_sha_found = true
        break 
      end
    end
    if cbc_sha_found then
      break
    end
  end

  -- Check for TLS compression
  for protocol, data in pairs(all_supported_ciphers) do
    local compressors = find_compressors(host, port, protocol, data.ciphers)
    if compressors then
      for _, compressor in ipairs(compressors) do
        if compressor ~= "NULL" then
          table.insert(alerts.critical, 
            string.format("TLS compression is enabled: %s compression (Protocol: %s)", 
            compressor, protocol))
        end
      end
    end
  end

  -- Alert on self-signed certificate
  if is_self_signed(cert) then
    table.insert(alerts.critical, "Self-signed certificate detected")
  end

  -- ====================================
  -- 3.2 HIGH ALERTS
  -- ====================================

  -- Check supported protocols
  if not all_supported_ciphers["TLSv1.2"] and not all_supported_ciphers["TLSv1.3"] then
    table.insert(alerts.high, "Server does not support TLS 1.2 or TLS 1.3")
  end

  -- Check cipher suites against recommended list
  for protocol, data in pairs(all_supported_ciphers) do
    for _, cipher in ipairs(data.ciphers) do
      if not is_cipher_recommended(cipher) then
        table.insert(alerts.high, 
          string.format("Unapproved TLS cipher: %s (Protocol: %s)", cipher, protocol))
      end
    end
  end

  -- Valid certificate public key type and size
  local valid_type, reason = validate_certificate_key(cert)
  if not valid_type then
    table.insert(alerts.high, reason)
  end

  -- ====================================
  -- 3.3 MEDIUM ALERTS
  -- ====================================

  -- Adequate certificate lifespan
  local cert_lifespan = get_cert_lifespan_days(cert)
  if cert_lifespan == -1 then
    table.insert(alerts.medium, "Certificate has an invalid lifespan.")
  elseif cert_lifespan < 90 then
    table.insert(alerts.medium, 
      string.format("Certificate lifespan is %d days (less than recommended 90 days)", cert_lifespan))
  elseif cert_lifespan > 366 then
    table.insert(alerts.medium, 
      string.format("Certificate lifespan is %d days (more than recommended 366 days)", cert_lifespan))
  end

  -- Domain matching
  local domain_match, reason = validate_domain_match(host.targetname or host.ip, cert)
  if not domain_match then
    table.insert(alerts.medium, reason)
  end

  -- ====================================
  -- 3.4 LOW ALERTS
  -- ====================================

  -- Avoid non-qualified host names in certificate
  local non_qualified_hosts_list = get_non_qualified_hosts(cert)
  if #non_qualified_hosts_list > 0 then
    local alert_message = "Certificate contains non-qualified host names in CN or SAN: " .. 
                         table.concat(non_qualified_hosts_list, ", ")
    table.insert(alerts.low, alert_message)
  end

  -- Avoid IP addresses in certificate
  local ip_findings = get_ip_addresses(cert)
  if #ip_findings > 0 then
    local alert_message = "Certificate contains IP addresses in CN or SAN: " .. 
                         table.concat(ip_findings, ", ")
    table.insert(alerts.low, alert_message)
  end

  -- ====================================
  -- 3.5 ENHANCED FUNCTIONALITY ALERTS
  -- ====================================

  -- HSTS Header Check
  local http_response = http.get(host, port, "/")

  if http_response and http_response.header then
    local header_hsts = http_response.header["strict-transport-security"]
    if header_hsts then
      local max_age_str = string.match(header_hsts, "max%-age=%s*(%d+)")
      if max_age_str then
        local max_age = tonumber(max_age_str)
        if max_age < 63072000 then
          table.insert(alerts.medium, 
            string.format("[ENHANCED] HSTS max-age is less than 2 years: %d seconds", max_age))
        end
      end
    else
      table.insert(alerts.high, "[ENHANCED] HSTS header is not set in HTTPS server")
    end

    -- Server Information Disclosure
    local server_info_alerts = check_server_info_disclosure(http_response)
    if #server_info_alerts > 0 then
      for _, alert in ipairs(server_info_alerts) do
        table.insert(alerts.medium, string.format(
          "[ENHANCED] Server information disclosure in %s header: %s (version: %s)", 
          alert.header, alert.value, alert.version
        ))
      end
    end
  else
    stdnse.debug(1, "[DEBUG] HTTP request failed or no headers received")
  end

-- TLS Curves
-- TO DO

-- DH Parameter Size
-- TO DO

  -- Wildcard Certificate Scope
  local wildcard_findings = get_wildcard_domains(cert)
  if #wildcard_findings > 0 then
    local alert_message = "[ENHANCED] Wildcard certificate scope: The following domains in CN or SAN use wildcards: " .. 
                         table.concat(wildcard_findings, ", ")
    table.insert(alerts.low, alert_message)
  end

  -- CN and SAN Attributes
  local cn_and_san_compatible, reason = validate_cn_san_compatibility(cert)
  if not cn_and_san_compatible then
    table.insert(alerts.low, reason)
  end

  -- Cipher Preference (test for TLS 1.2 as representative)
  for protocol, data in pairs(all_supported_ciphers) do
    local ciphers = data.ciphers
    local entity, err = find_cipher_preference(host, port, protocol, ciphers)
    if not entity then
      stdnse.debug(1, "[DEBUG] Could not determine cipher preference: %s", err)
    elseif entity == "client" then
      table.insert(alerts.low, "[ENHANCED] Server follows client cipher preference")
      break
    end
  end

  -- 4. Output formatting
  local result = format_alerts(alerts)
  
  -- Debug: summary of supported ciphers
  for protocol, data in pairs(all_supported_ciphers) do
    stdnse.debug(1, "[DEBUG] Supported ciphers for %s: %d", protocol, #data.ciphers)
    for i, cipher in ipairs(data.ciphers) do
      stdnse.debug(2, "[DEBUG]   [%d] %s", i, cipher)
    end
  end
  
  return stdnse.format_output(true, result)
end