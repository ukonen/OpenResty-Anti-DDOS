--[[
	Ukonen's OpenResty Anti-DDOS script.
]]

--[[
	Notes: It may be worth minifying the js/html sections if you want to save a small amount of bandwidth.

	You must add this to your nginx config to get the script to work.

	http {
		lua_shared_dict antiddos 24m;
		access_by_lua_file lua/anti-ddos.lua;
	}
]]

--[[
	Configuration section
]]

-- obfuscate cookies?
local obfuscate_cookies = true

-- This is essential for the cryptography [ change this from the default ]
local hashing_salt = "PJz3Oo4AZfw1"

-- Name of the authentication cookie ( if it's not set to obfuscate )
local authentication_cookie_name = "ddos_authentication"

-- How long the client should be authenticated for after solving a challenge
local authentication_time = 43200 -- 12 hours, value is in seconds

-- Challenge strength ( How hard will the client have to work to get the answer? )
local max_challenge_strength = 100000
local min_challenge_strength = 30000

--[[
	Define our variables
]]

-- Shared lua dictionary object
local shared_antiddos = ngx.shared.antiddos

--[[
	Start our actual code lol
]]

-- Setup sha512 ( TODO: compare speed of resty.sha1 and ngx.sha1_bin )
local resty_string = require "resty.string"
local resty_sha512 = require "resty.sha512"
local sha512 = resty_sha512:new()

local function sha512_string(message)
	sha512:update(tostring(message))
	local hashed_string = resty_string.to_hex(sha512:final())
	sha512:reset()
	return hashed_string
end

-- Get the ip address of the client
local client_ip = tostring(ngx.var.remote_addr)

-- Get the time ( subtracting unix time because that's slightly less ram usage!!! )
local minimal_time = os.time() - 1700000000

-- Check the if the client already exists in the dictionary
local client_solution, client_flag = shared_antiddos:get(client_ip)

-- Obfuscate cookies
if obfuscate_cookies then
	authentication_cookie_name = sha512_string(client_ip .. hashing_salt)
end

-- Client has came here before
if client_solution and client_flag and client_flag > minimal_time then
	-- Since the client has came here before lets check if they have the answer
	local authentication_cookie = ngx.var["cookie_" .. authentication_cookie_name] or ""

	if authentication_cookie == client_solution then
		-- They passed the checks, let them go see the client
		ngx.exit(ngx.OK)
	end
else
	-- Change the lua random seed
	math.randomseed(minimal_time + math.random(1, 5000))

	-- Create the answer for the client ( dont define the expire time because it has a resolution of 0.001s lol )
	client_solution = tostring(math.random(min_challenge_strength, max_challenge_strength))
	shared_antiddos:set(client_ip, client_solution, 0, minimal_time + authentication_time)
end

--[[
	Client failed verification checks so send them the page to let them solve the puzzle
]]

-- Before that, lets just check if it's a proper request
local request_headers = ngx.req.get_headers()
if request_headers["Sec-Fetch-Mode"] ~= "navigate" then
	ngx.header["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval';"
	ngx.header["Cache-Control"] = "public, max-age=0 no-store, no-cache, must-revalidate, post-check=0, pre-check=0"
	ngx.header["Pragma"] = "no-cache"
	ngx.header["Expires"] = "0"
	ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

-- Documentation for the regex options ( https://github.com/openresty/lua-nginx-module#ngxrematch )
local converted_client_ip = ngx.re.gsub(client_ip, "[.]", "", "Ujos")
local user_agent = ngx.var.http_user_agent

-- Define the javascript puzzle the client has to solve ( ideally you should change this )
local javascript_puzzle = [[
	document.addEventListener("DOMContentLoaded", async () => {
		const text_encoder = new TextEncoder("utf-8");
		const client_ip = ]] .. converted_client_ip .. [[;
		const challenge_wanted = "]] .. sha512_string(converted_client_ip + client_solution) .. [[";

		async function sha512(message) {
			const hash_buffer = await crypto.subtle.digest("SHA-512", text_encoder.encode(message));
			return Array.prototype.map.call(new Uint8Array(hash_buffer), b => (("00" + b.toString(16)).slice(-2))).join("");
		}

		for (let i=0; i < ]] .. max_challenge_strength .. [[; i++) {
			if ( await sha512(client_ip + i) == challenge_wanted ) {
				document.cookie = "]] .. authentication_cookie_name .. [[=" + i + "; max-age=]] .. authentication_time .. [[; path=/; Secure";
				break;
			}
		}

		location.reload(true);
	});
]]

-- HTML used in the page they'll see for verification
local verification_html = [[
<!DOCTYPE html>
<html>
	<head>
		<meta charset="utf-8"/>
		<meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<meta name="robots" content="noindex, nofollow"/>
		<title>DDOS Prevention</title>
		<style type="text/css">
			body {
				background: #000;
				color: #fff;

				max-width: 65rem;
				margin: auto;

				letter-spacing: -0.02em;
				word-wrap: break-word;
				font: 10pt monospace;
				line-height: 1.5em;
			}

			h1 { color: #808000; font-size: 120%; margin-top: 0; margin-bottom: 0; }
			ul { margin-top: 0.5em; }

			.banner {
				margin-bottom: 0.5em;
				line-height: 1.1em;
				font-size: 9pt;
			}

			@media (max-width: 720px) {
				.banner {font-size: 1.65vw;}
			}
		</style>
		<script type="text/javascript" charset="utf-8">]] .. javascript_puzzle .. [[</script>
	</head>
	<body>
		<div id="status">
			<noscript><h1>Please enable javascript and reload the page.</h1><br></noscript>
			<h1>Your browser will redirect to the requested content shortly.</h1>
			<h1>Currently solving a cryptographic challenge...</h1>
		</div>
		<ul>
			<li>User-Agent: ]] .. user_agent .. [[</li>
			<li>IP Address: ]] .. client_ip .. [[</li>
		</ul>
	</body>
</html>
]]

-- Send the client the javascript challenge
ngx.header["X-Content-Type-Options"] = "nosniff"
ngx.header["X-Frame-Options"] = "SAMEORIGIN"
ngx.header["X-XSS-Protection"] = "1; mode=block"
ngx.header["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval';"
ngx.header["Cache-Control"] = "public, max-age=0 no-store, no-cache, must-revalidate, post-check=0, pre-check=0"
ngx.header["Pragma"] = "no-cache"
ngx.header["Expires"] = "0"
ngx.header.content_type = "text/html; charset=utf-8"
ngx.say(verification_html)
ngx.exit(ngx.HTTP_OK)
