-- helpers.lua — internal utilities for the openssl driver.
local H = {}

-- -------------------------------------------------------------------------
-- Constants
-- -------------------------------------------------------------------------

H.DEFAULT_OPTIONS = {
	salt = true,
	base64 = true,
	cipher = "aes-256-cbc",
	encryption_method = "passphrase",
	auto_decrypt_on_open = true,
	pbkdf2 = {
		iterations = 100000,
		digest = "sha256",
	},
	file_patterns = { "*.enc", "*.enc.*" },
	passphrase = {
		source = "prompt",
		env_var = "ENCBUF_OPENSSL_PASSPHRASE",
		confirm = true,
		cache = true,
		cache_timeout = 300,
	},
	key = {
		source = "env",
		key_env_var = "ENCBUF_OPENSSL_KEY",
		iv_env_var = "ENCBUF_OPENSSL_IV",
		encoding = "hex",
	},
	openssl = {
		bin = "openssl",
		extra_args = {},
	},
}

-- openssl supports a lot of ciphers, but we only allow the most common secure
-- ones for now and add as needed.
H.SUPPORTED_CIPHERS = {
	"aes-256-cbc",
	"aes-256-ctr",
	"chacha20",
}

-- -------------------------------------------------------------------------
-- Passphrase cache (module-level, lives for the Neovim session)
-- -------------------------------------------------------------------------

H.cache = {
	passphrase = {
		value = nil,
		at = 0,
	},
}

--- Invalidate the passphrase cache (e.g. after a failed decryption).
function H.clear_cache()
	H.cache.passphrase.value = nil
	H.cache.passphrase.at = 0
end

--- Resolve the passphrase from cache, env var, or interactive prompt.
---
--- The passphrase is passed to openssl via stdin (fd 0), NOT as a command-line
--- argument, so it never appears in `ps` or other process-listing tools.
--- For this to work the passphrase must not contain a newline character.
---
--- @param options  table               driver options
--- @param confirm  boolean             ask twice on new-file encrypt
--- @param callback fun(pass: string|nil)
function H.get_passphrase(options, confirm, callback)
	local passphrase_options = options.passphrase

	if passphrase_options.cache and H.cache.passphrase.value then
		if (os.time() - H.cache.passphrase.at) < passphrase_options.cache_timeout then
			return callback(H.cache.passphrase.value)
		end
		H.cache.passphrase.value = nil
	end

	if passphrase_options.source == "env" then
		local pass = vim.env[passphrase_options.env_var]
		if not pass or pass == "" then
			vim.notify("[encbuf] $" .. passphrase_options.env_var .. " is not set", vim.log.levels.ERROR)
			return callback(nil)
		end
		if pass:find("\n") then
			vim.notify("[encbuf] Passphrase must not contain newline characters", vim.log.levels.ERROR)
			return callback(nil)
		end
		if passphrase_options.cache then
			H.cache.passphrase.value = pass
			H.cache.passphrase.at = os.time()
		end
		return callback(pass)
	end

	local pass = vim.fn.inputsecret("encbuf passphrase: ")
	if not pass or pass == "" then
		return callback(nil)
	end
	if confirm and passphrase_options.confirm then
		local again = vim.fn.inputsecret("Confirm passphrase: ")
		if pass ~= again then
			vim.notify("[encbuf] Passphrases do not match", vim.log.levels.ERROR)
			return callback(nil)
		end
	end
	if pass:find("\n") then
		vim.notify("[encbuf] Passphrase must not contain newline characters", vim.log.levels.ERROR)
		return callback(nil)
	end
	if passphrase_options.cache then
		H.cache.passphrase.value = pass
		H.cache.passphrase.at = os.time()
	end
	callback(pass)
end

--- Convert a byte string to its lowercase hex representation.
---
--- @param s string
--- @return string
local function to_hex(s)
	return (s:gsub(".", function(c)
		return string.format("%02x", c:byte())
	end))
end

--- Resolve the raw key and IV for the "key" encryption method.
---
--- Both values are returned as lowercase hex strings (the format openssl -K/-iv
--- expects). If the configured encoding is "base64" they are decoded first.
---
--- @param options  table               driver options
--- @param callback fun(key: string|nil, iv: string|nil)
function H.get_key(options, callback)
	local cfg = options.key

	local function decode(raw, label)
		if cfg.encoding == "hex" then
			return raw
		end
		local ok, decoded = pcall(vim.base64.decode, raw)
		if not ok then
			vim.notify("[encbuf] " .. label .. ": invalid base64", vim.log.levels.ERROR)
			return nil
		end
		return to_hex(decoded)
	end

	if cfg.source == "env" then
		local key_raw = vim.env[cfg.key_env_var]
		if not key_raw or key_raw == "" then
			vim.notify("[encbuf] $" .. cfg.key_env_var .. " is not set", vim.log.levels.ERROR)
			return callback(nil, nil)
		end
		local iv_raw = vim.env[cfg.iv_env_var]
		if not iv_raw or iv_raw == "" then
			vim.notify("[encbuf] $" .. cfg.iv_env_var .. " is not set", vim.log.levels.ERROR)
			return callback(nil, nil)
		end
		local key = decode(key_raw, "key")
		if not key then
			return callback(nil, nil)
		end
		local iv = decode(iv_raw, "IV")
		if not iv then
			return callback(nil, nil)
		end
		return callback(key, iv)
	end

	local key_raw = vim.fn.inputsecret("encbuf key (" .. cfg.encoding .. "): ")
	if not key_raw or key_raw == "" then
		return callback(nil, nil)
	end
	local iv_raw = vim.fn.inputsecret("encbuf IV (" .. cfg.encoding .. "): ")
	if not iv_raw or iv_raw == "" then
		return callback(nil, nil)
	end
	local key = decode(key_raw, "key")
	if not key then
		return callback(nil, nil)
	end
	local iv = decode(iv_raw, "IV")
	if not iv then
		return callback(nil, nil)
	end
	callback(key, iv)
end

--- Build the openssl enc argument list (without -pass, which is added by run_openssl).
---
--- @param options table driver options
--- @param decrypt boolean true for decryption, false for encryption
--- @return string[]
function H.build_args(options, decrypt)
	local args = { "enc", "-" .. options.cipher }

	if decrypt then
		table.insert(args, "-d")
	end

	if options.base64 then
		table.insert(args, "-base64")
	end

	-- Salt and PBKDF2 are only relevant for passphrase-based key derivation.
	-- Passing -salt/-nosalt with explicit -K/-iv is an error in OpenSSL 3.x.
	if options.encryption_method == "passphrase" then
		if options.salt then
			table.insert(args, "-salt")
		else
			table.insert(args, "-nosalt")
		end
		table.insert(args, "-pbkdf2")
		table.insert(args, "-iter")
		table.insert(args, tostring(options.pbkdf2.iterations))
		table.insert(args, "-md")
		table.insert(args, options.pbkdf2.digest)
	end

	for _, arg in ipairs(options.openssl.extra_args) do
		table.insert(args, arg)
	end

	return args
end

--- Spawn openssl enc and stream data through stdin/stdout pipes.
---
--- When a passphrase is provided it is sent as the first line of stdin via
--- `-pass stdin` (fd 0) so it never appears in the process argument list
--- (`ps`, `/proc/<pid>/cmdline`) and no temporary file is created.
--- stdin layout with passphrase:  <passphrase>\n<input_data>
--- stdin layout without:          <input_data>
---
--- @param args       string[]      openssl enc arguments (without -pass)
--- @param input      string        data to encrypt or decrypt
--- @param passphrase string|nil    nil for raw key/iv method
--- @param options    table         driver options
--- @return string|nil  output on success
--- @return string|nil  error message on failure
function H.run_openssl(args, input, passphrase, options)
	local stdin_pipe = vim.loop.new_pipe(false)
	local stdout_pipe = vim.loop.new_pipe(false)
	local stderr_pipe = vim.loop.new_pipe(false)

	local stdin_data
	if passphrase then
		table.insert(args, "-pass")
		table.insert(args, "stdin")
		stdin_data = passphrase .. "\n" .. input
	else
		stdin_data = input
	end

	local stdout_chunks = {}
	local stderr_chunks = {}
	local exit_code = nil

	local handle = vim.loop.spawn(options.openssl.bin, {
		args = args,
		stdio = { stdin_pipe, stdout_pipe, stderr_pipe },
	}, function(code)
		exit_code = code
	end)

	if not handle then
		return nil, "Failed to spawn: " .. options.openssl.bin
	end

	stdout_pipe:read_start(function(_, data)
		if data then
			table.insert(stdout_chunks, data)
		end
	end)

	stderr_pipe:read_start(function(_, data)
		if data then
			table.insert(stderr_chunks, data)
		end
	end)

	stdin_pipe:write(stdin_data, function()
		stdin_pipe:shutdown(function()
			stdin_pipe:close()
		end)
	end)

	local ok = vim.wait(10000, function()
		return exit_code ~= nil
	end, 10)

	if not stdout_pipe:is_closing() then
		stdout_pipe:close()
	end
	if not stderr_pipe:is_closing() then
		stderr_pipe:close()
	end
	handle:close()

	if not ok then
		return nil, "openssl timed out"
	end

	if exit_code ~= 0 then
		local msg = table.concat(stderr_chunks, "")
		return nil, ("openssl exited %d: %s"):format(exit_code, msg)
	end

	return table.concat(stdout_chunks, ""), nil
end

return H
