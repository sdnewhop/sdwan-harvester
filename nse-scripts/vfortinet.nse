local http = require "http"
local url = require "url"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local shortport = require "shortport"

description = [[
The script for getting the product version of Fortinet FortiGate SD-WAN
]]


author = {"sdnewhop"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

local function fail (err) return stdnse.format_output(false, err) end

action = function(host, port)
  local resp_js_path, js_path, resp_js
  local conf_build, conf_model, conf_label
  local output_info = {}
  local version

  local resp = http.get(host, port, "/")
  local version = nil

  -- make redirect if needed
  if resp.status == 301 or resp.status == 302 then
    local url = url.parse( resp.header.location )
    if url.host == host.targetname or url.host == ( host.name ~= '' and host.name ) or url.host == host.ip then
      stdnse.print_debug("Redirect: " .. host.ip .. " -> " .. url.scheme.. "://" .. url.authority .. url.path)
      -- extract redirect port
      redir_port = string.match(url.authority, ":(%d+)")
      stdnse.print_debug("Redirect port is: " .. redir_port)
      stdnse.print_debug("Trying to get " .. host.ip .. " at " .. redir_port .. " port")
      -- get Fortinet login page at custom port
      resp = http.get(host.ip, tonumber(redir_port), "/login")
    end
  end

  if not resp.body then
    return nil
  end

  -- check if it Fortinet or not
  if not string.match(resp.body:lower(), "fortinet") then
    return nil
  end
  stdnse.print_debug("Found Fortinet SD-WAN")

  -- trigger 401 error to find path to js file with version
  resp_js_path = http.get(host.ip, tonumber(redir_port), "/api")
  if not resp_js_path.body then
    return nil
  end

  -- search for js file that contains version
  js_path = string.match(resp_js_path.body:lower(), "<script src=\"(/%w+/fweb_all.js)")
  if not js_path then
    return nil
  end
  stdnse.print_debug("Found js path: " .. js_path)

  -- get founded js and grep for version
  resp_js = http.get(host.ip, tonumber(redir_port), js_path)
  if not resp_js_path.body then
    return nil
  end
  stdnse.print_debug("Js - founded")

  -- parse versions
  conf_build = string.match(resp_js.body, "CONFIG_BUILD_NUMBER:(%d+)")
  conf_model = string.match(resp_js.body, "CONFIG_MODEL:\"([%w_]+)\"")
  conf_label = string.match(resp_js.body, "CONFIG_BUILD_LABEL:\"([%w_]+)\"")
  if (not conf_build) or (not conf_model) or (not conf_label) then
    return nil
  end

  output_info = stdnse.output_table()
  output_info.vsdwan_version = {}

  version = "build " .. conf_build .. ", model " .. conf_model .. " (" .. conf_label .. ")"
  table.insert(output_info.vsdwan_version, "Fortinet FortiGate Version: " .. version)

  return output_info, stdnse.format_output(true, output_info)
end
