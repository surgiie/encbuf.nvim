-- Driver: openssl
-- @link: https://openssl.org/docs/man1.1.1/man1/enc.html
local M = {}
local DRIVER_HELPERS = require("encbuf.drivers.openssl.helpers")
local HELPERS = require("encbuf.helpers")

--- Invalidate the passphrase cache (e.g. after a failed decryption).
function M.clear_cache()
	DRIVER_HELPERS.clear_cache()
end

--- Resolve and validate openssl driver options.
---
--- @param options table
--- @return table
function M.validate_options(options)
	local patterns = DRIVER_HELPERS.DEFAULT_OPTIONS.file_patterns
	options = vim.tbl_deep_extend("force", DRIVER_HELPERS.DEFAULT_OPTIONS, options or {})

	options.file_patterns = vim.iter({ patterns, options.file_patterns }):flatten():totable()

	vim.validate({
		auto_decrypt_on_open = { options.auto_decrypt_on_open, "boolean" },
		cipher = { options.cipher, HELPERS.one_of("cipher", DRIVER_HELPERS.SUPPORTED_CIPHERS) },
		encryption_method = { options.encryption_method, HELPERS.one_of("encryption_method", { "passphrase", "key" }) },
		base64 = { options.base64, "boolean" },
		salt = { options.salt, "boolean" },
		passphrase = { options.passphrase or {}, "table" },
		file_patterns = { options.file_patterns, "table" },
		["passphrase.source"] = { options.passphrase.source, HELPERS.one_of("passphrase.source", { "prompt", "env" }) },
		["passphrase.confirm"] = { options.passphrase.confirm, "boolean" },
		["passphrase.cache"] = { options.passphrase.cache, "boolean" },
		["passphrase.cache_timeout"] = { options.passphrase.cache_timeout, "number" },
		key = { options.key or {}, "table" },
		["key.source"] = { options.key.source, HELPERS.one_of("key.source", { "prompt", "env" }) },
		["key.encoding"] = { options.key.encoding, HELPERS.one_of("key.encoding", { "hex", "base64" }) },
		["key.key_env_var"] = { options.key.key_env_var, "string" },
		["key.iv_env_var"] = { options.key.iv_env_var, "string" },
		openssl = { options.openssl or {}, "table" },
		["openssl.bin"] = { options.openssl.bin, "string" },
		["openssl.extra_args"] = { options.openssl.extra_args, "table" },
	})

	return options
end

--- Encrypt plaintext with the configured method.
---
--- @param plain_text string
--- @param options    table
--- @param callback   fun(result: string|nil)
function M.encrypt(plain_text, options, callback)
	if options.encryption_method == "passphrase" then
		-- confirm=true: when there is no cached passphrase the user is asked
		-- to type it twice (guards against typos on a new file's first save).
		DRIVER_HELPERS.get_passphrase(options, true, function(pass)
			if not pass then
				return callback(nil)
			end
			local args = DRIVER_HELPERS.build_args(options, false)
			local result, err = DRIVER_HELPERS.run_openssl(args, plain_text, pass, options)
			if not result then
				vim.notify("[encbuf] Encryption failed: " .. (err or "unknown error"), vim.log.levels.ERROR)
				return callback(nil)
			end
			callback(result)
		end)
	else
		DRIVER_HELPERS.get_key(options, function(key, iv)
			if not key then
				return callback(nil)
			end
			local args = DRIVER_HELPERS.build_args(options, false)
			table.insert(args, "-K")
			table.insert(args, key)
			table.insert(args, "-iv")
			table.insert(args, iv)
			local result, err = DRIVER_HELPERS.run_openssl(args, plain_text, nil, options)
			if not result then
				vim.notify("[encbuf] Encryption failed: " .. (err or "unknown error"), vim.log.levels.ERROR)
				return callback(nil)
			end
			callback(result)
		end)
	end
end

--- Decrypt encrypted content with the configured method.
---
--- @param encrypted_content string
--- @param options            table
--- @param callback           fun(result: string|nil)
function M.decrypt(encrypted_content, options, callback)
	if options.encryption_method == "passphrase" then
		-- confirm=false: decryption never needs the passphrase confirmed.
		DRIVER_HELPERS.get_passphrase(options, false, function(pass)
			if not pass then
				return callback(nil)
			end
			local args = DRIVER_HELPERS.build_args(options, true)
			-- openssl requires a trailing newline after base64-encoded input;
			-- without it, it errors with "error reading input file".
			local input = options.base64 and (encrypted_content .. "\n") or encrypted_content
			local result, err = DRIVER_HELPERS.run_openssl(args, input, pass, options)
			if not result then
				-- Bad passphrase is the most likely cause; evict the cache so the
				-- user is re-prompted on the next attempt.
				M.clear_cache()
				vim.notify("[encbuf] Decryption failed: " .. (err or "unknown error"), vim.log.levels.ERROR)
				return callback(nil)
			end
			callback(result)
		end)
	else
		DRIVER_HELPERS.get_key(options, function(key, iv)
			if not key then
				return callback(nil)
			end
			local args = DRIVER_HELPERS.build_args(options, true)
			table.insert(args, "-K")
			table.insert(args, key)
			table.insert(args, "-iv")
			table.insert(args, iv)
			local input = options.base64 and (encrypted_content .. "\n") or encrypted_content
			local result, err = DRIVER_HELPERS.run_openssl(args, input, nil, options)
			if not result then
				vim.notify("[encbuf] Decryption failed: " .. (err or "unknown error"), vim.log.levels.ERROR)
				return callback(nil)
			end
			callback(result)
		end)
	end
end

return M
