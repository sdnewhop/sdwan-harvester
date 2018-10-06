local http = require "http"
local url = require "url"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local shortport = require "shortport"

description = [[
The script for getting the product version of VMWare NSX SD-WAN
]]


author = {"afr"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

local function fail (err) return stdnse.format_output(false, err) end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"
  local response
  local output_info = {}
  local vsdwan = ""
  local urlp = path

  response = http.generic_request(host, port, "GET", path)

  if response.status == 301 or response.status == 302 then
    local url_parse_res = url.parse(response.header.location)
    urlp = url_parse_res.path
    stdnse.print_debug("Status code: " .. response.status)
    response = http.generic_request(host,port,"GET", urlp)
  end

  output_info = stdnse.output_table()

  if response == nil then
    return fail("Request failed")
  end

  local try_counter = 1

  while try_counter < 6 and response.status ~= 200 do
    response = http.generic_request(host, port, "GET", urlp) 
    try_counter = try_counter + 1
  end

  if response.status == 200 then

    found, matches = http.response_contains(response, "%/vco%-ui.([0-9.]+).", false)
    if found == true then vsdwan = matches[1] else return nil end
    
    output_info.vsdwan_version = {}
    table.insert(output_info.vsdwan_version, "VMware NSX Version: " .. vsdwan)
  end

  return output_info, stdnse.format_output(true, output_info)

end

