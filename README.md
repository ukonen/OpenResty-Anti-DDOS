# OpenResty Anti-DDOS
An alternative Anti-DDOS script to C0nw0nks, that aims to be more lightweight and prevent all automated requests.
I highly recommend you to read the script for yourself and make tweaks if necessary as by default it aims to be as lightweight as possible.

## Installation
Add `anti-ddos.lua` to your lua folder that's next to your `nginx.conf` file,
Here's an example, if `nginx.conf` is inside `/etc/nginx/` then you should move `anti-ddos.lua` to `/etc/nginx/lua/anti-ddos.lua`
Once you've done that, you need to add the following configuration to your existing `http {}` block within `nginx.conf` to to make the script get ran.
```
lua_shared_dict antiddos 24m;
access_by_lua_file lua/anti-ddos.lua;
```

<details>
  <summary>Example http {} block within nginx.lua</summary>
  ```lua
  http {
  	#
  	# General configuration
  	#
  
  	# Serve resources with the proper media types (f.k.a. MIME types).
  	include mime.types;
  	default_type application/octet-stream;
  	# Speed up file transfers by using `sendfile()` to copy directly
  	sendfile on;
  	# Let the server close connections for non-responsive clients
  	reset_timedout_connection on;
  	# Dont log errors about files that don't exist
  	log_not_found off;
  	# No TCP delay ( disables Nagle's algorithm )
  	tcp_nodelay on;
  	# Don't send out partial frames
  	tcp_nopush on;
  	# Dont send our openresty version number
  	server_tokens off;
  
  	#
  	# Header configuration
  	#
  
  	# Enables xss filtering, browser will prevent rendering of the page if an attack is detected
  	add_header X-XSS-Protection "1; mode=block";
  	# Blocks a request if the request destination is of type style and the mime type is not text/css
  	add_header X-Content-Type-Options nosniff;
  	# The page can only be displayed if all ancestor frames are same origin to the page itself
  	add_header X-Frame-Options SAMEORIGIN;
  	# Hide 'X-Powered-By' header which shows we use openresty
  	proxy_hide_header X-Powered-By;
  
  	#
  	# Logging configuration
  	#
  
  	# only log critical errors
  	error_log error.log;
  
  	#
  	# OpenResty scripts ( ADD THIS SECTION )
  	#
  
  	# Ukonen's Anti-DDOS script
  	lua_shared_dict antiddos 24m;
  	access_by_lua_file lua/anti-ddos.lua;
  }
  ```
</details>
