-- encbuf/init.lua - Transparent encryption for buffers.
-- Env:
--      ENCBUF_OPENSSL_PASSPHRASE - auto-use passphrase without prompting.

local ENCBUF = {}
local HELPERS = require("encbuf.helpers")

-- bufnr -> state for active encrypted buffers:
--   true      buffer has plaintext, transparent mode (:w re-encrypts)
--   "writing" encryption in progress (re-entrancy guard)
--   "locked"  buffer shows ciphertext, file is encrypted on disk
--             (:w is a no-op; use :EncBufDecrypt to unlock)
local encrypted_buffers = {}

--- Disable options that could leak plaintext to disk for a given buffer.
--- Must be called inside nvim_buf_call so opt_local targets the right buffer.
local function disable_plaintext_leak_options()
	vim.opt_local.undofile = false
	vim.opt_local.swapfile = false
end

-- -------------------------------------------------------------------------
-- Autocmds
-- -------------------------------------------------------------------------

--- Setup autocommands for handling encryption/decryption on buffer events.
--- @param driver  table  driver module
--- @param options table  validated driver options
local function setup_autocmds(driver, options)
	local group = vim.api.nvim_create_augroup("EncBuf", { clear = true })

	-- New file that does not yet exist on disk: nothing to decrypt.
	vim.api.nvim_create_autocmd("BufNewFile", {
		group = group,
		pattern = options.file_patterns,
		callback = function(ev)
			local bufnr = ev.buf
			if encrypted_buffers[bufnr] then
				return
			end
			encrypted_buffers[bufnr] = true
			vim.api.nvim_buf_call(bufnr, disable_plaintext_leak_options)
			vim.defer_fn(function()
				vim.notify(
					"New encrypted file — content will be encrypted on save",
					vim.log.levels.INFO,
					{ title = "encbuf.nvim", timeout = 5000 }
				)
			end, 50)
		end,
	})

	--- Read ciphertext from disk and decrypt it into bufnr.
	--- Defers to the next event-loop tick so noice.nvim is ready before the prompt.
	--- @param bufnr integer
	local function decrypt_buffer(bufnr)
		local filepath = vim.api.nvim_buf_get_name(bufnr)

		-- Always read from disk so retries see the original ciphertext even if
		-- the buffer was modified (e.g. after a failed decrypt left ciphertext in it).
		local mode = options.base64 and "r" or "rb"
		local f, ferr = io.open(filepath, mode)
		if not f then
			vim.notify("[encbuf] Cannot read file: " .. (ferr or filepath), vim.log.levels.ERROR)
			encrypted_buffers[bufnr] = nil
			return
		end
		local content = f:read("*a")
		f:close()

		-- Base64 ciphertext is stored with a trailing newline by writefile; strip it
		-- to match what openssl expects (it will re-add one via -base64).
		if options.base64 and content:sub(-1) == "\n" then
			content = content:sub(1, -2)
		end

		-- Defer until the next event-loop tick so that UI plugins like
		-- noice.nvim have finished registering their handlers before the
		-- inputsecret prompt fires.
		vim.schedule(function()
			driver.decrypt(content, options, function(plain)
				if not plain then
					-- Decryption failed; clear the guard so the user can retry.
					encrypted_buffers[bufnr] = nil
					return
				end

				local plain_lines = vim.split(plain, "\n", { plain = true })
				-- Drop trailing empty element produced by a trailing newline in the output.
				if plain_lines[#plain_lines] == "" then
					table.remove(plain_lines)
				end

				-- Replace buffer contents without adding an undo entry.
				-- Setting undolevels=-1 for this one operation makes the decrypted
				-- state the base state (users cannot undo back to the raw ciphertext,
				-- and the in-memory undo tree holds no plaintext "before" state).
				local saved_undolevels = vim.bo[bufnr].undolevels
				vim.bo[bufnr].undolevels = -1
				vim.api.nvim_buf_set_lines(bufnr, 0, -1, false, plain_lines)
				vim.bo[bufnr].undolevels = saved_undolevels

				vim.bo[bufnr].modified = false
			end)
		end)
	end

	-- After an existing file is loaded: decrypt its content in-place.
	vim.api.nvim_create_autocmd("BufReadPost", {
		group = group,
		pattern = options.file_patterns,
		callback = function(ev)
			local bufnr = ev.buf
			if encrypted_buffers[bufnr] then
				return
			end

			vim.api.nvim_buf_call(bufnr, disable_plaintext_leak_options)

			local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
			local is_empty = #lines == 0 or (#lines == 1 and lines[1] == "")
			if is_empty then
				return
			end

			if not options.auto_decrypt_on_open then
				return
			end

			-- Mark early: vim.wait inside run_openssl pumps the event loop and
			-- could re-trigger this autocmd for the same buffer without the guard.
			encrypted_buffers[bufnr] = true
			decrypt_buffer(bufnr)
		end,
	})

	-- Manual decrypt: also used to unlock a buffer locked by :EncBufEncrypt.
	vim.api.nvim_create_user_command("EncBufDecrypt", function()
		local bufnr = vim.api.nvim_get_current_buf()
		local filepath = vim.api.nvim_buf_get_name(bufnr)
		if not filepath or filepath == "" then
			vim.notify("[encbuf] No file associated with this buffer", vim.log.levels.ERROR)
			return
		end

		if encrypted_buffers[bufnr] == true then
			vim.notify("[encbuf] Buffer is already decrypted", vim.log.levels.INFO)
			return
		end

		if driver.clear_cache then
			driver.clear_cache()
		end

		-- Reset the guard so decrypt_buffer treats this as a fresh attempt.
		-- Works for both nil (initial state) and "locked" (post-EncBufEncrypt).
		encrypted_buffers[bufnr] = true
		vim.api.nvim_buf_call(bufnr, disable_plaintext_leak_options)
		decrypt_buffer(bufnr)
	end, { desc = "Decrypt the current encrypted buffer (also unlocks a locked buffer)" })

	--- Encrypt the current plaintext in bufnr and write ciphertext to disk.
	--- on_success, if provided, is called with the encrypted string after the
	--- file is written — used by :EncBufEncrypt to lock the buffer.
	--- @param bufnr     integer
	--- @param on_success fun(encrypted: string)|nil
	local function encrypt_buffer(bufnr, on_success)
		if encrypted_buffers[bufnr] == "writing" then
			return
		end
		encrypted_buffers[bufnr] = "writing"

		local filepath = vim.api.nvim_buf_get_name(bufnr)
		local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
		local plain = table.concat(lines, "\n")

		driver.encrypt(plain, options, function(encrypted)
			if not encrypted then
				encrypted_buffers[bufnr] = true
				return
			end

			local write_ok
			if options.base64 then
				-- Base64 ciphertext is ASCII text; writefile handles it correctly.
				local enc_lines = vim.split(encrypted, "\n", { plain = true })
				-- Drop trailing empty element so the file doesn't gain a spurious newline.
				if enc_lines[#enc_lines] == "" then
					table.remove(enc_lines)
				end
				write_ok = vim.fn.writefile(enc_lines, filepath) == 0
			else
				-- Binary ciphertext: write raw bytes directly.
				-- vim.fn.writefile uses NUL-terminated Vimscript strings and would
				-- truncate on any NUL byte in the ciphertext, corrupting the file.
				local f, werr = io.open(filepath, "wb")
				if f then
					f:write(encrypted)
					f:close()
					write_ok = true
				else
					vim.notify("[encbuf] Write failed: " .. (werr or filepath), vim.log.levels.ERROR)
					write_ok = false
				end
			end

			if not write_ok then
				vim.notify("[encbuf] Write failed: " .. filepath, vim.log.levels.ERROR)
				encrypted_buffers[bufnr] = true
				return
			end

			-- Re-assert in case something else toggled either option back on.
			vim.api.nvim_buf_call(bufnr, disable_plaintext_leak_options)

			if on_success then
				on_success(encrypted)
			else
				-- Transparent mode (:w): keep plaintext in buffer.
				encrypted_buffers[bufnr] = true
				vim.bo[bufnr].modified = false
			end
		end)
	end

	-- Take full control of the write: encrypt then write ciphertext to disk.
	-- BufWriteCmd prevents Neovim's own write from running.
	vim.api.nvim_create_autocmd("BufWriteCmd", {
		group = group,
		pattern = options.file_patterns,
		callback = function(ev)
			local bufnr = ev.buf
			-- "locked" means the buffer already shows ciphertext — :w would
			-- double-encrypt it. Treat as a no-op (file is already encrypted).
			if encrypted_buffers[bufnr] == "locked" then
				vim.bo[bufnr].modified = false
				return
			end
			-- Prevent re-entrancy: vim.wait inside run_openssl pumps the event
			-- loop and could re-trigger this autocmd for the same buffer.
			encrypt_buffer(bufnr)
		end,
	})

	-- Manual encrypt: encrypts and locks the buffer (shows ciphertext) so the
	-- user can see the file is encrypted. Use :EncBufDecrypt to unlock.
	vim.api.nvim_create_user_command("EncBufEncrypt", function()
		local bufnr = vim.api.nvim_get_current_buf()
		local filepath = vim.api.nvim_buf_get_name(bufnr)
		if not filepath or filepath == "" then
			vim.notify("[encbuf] No file associated with this buffer", vim.log.levels.ERROR)
			return
		end

		if encrypted_buffers[bufnr] == "writing" then
			vim.notify("[encbuf] Encryption already in progress", vim.log.levels.INFO)
			return
		end

		if encrypted_buffers[bufnr] == "locked" then
			vim.notify("[encbuf] Buffer is already encrypted.", vim.log.levels.INFO)
			return
		end

		-- Ensure the buffer is tracked before encrypting.
		if not encrypted_buffers[bufnr] then
			encrypted_buffers[bufnr] = true
			vim.api.nvim_buf_call(bufnr, disable_plaintext_leak_options)
		end

		-- Defer to the next event-loop tick so vim.wait inside run_openssl
		-- works correctly — same reason decrypt_buffer uses vim.schedule.
		vim.schedule(function()
			encrypt_buffer(bufnr, function(encrypted)
				-- Lock mode: replace buffer with the ciphertext so the user
				-- can see the file is encrypted. :EncBufDecrypt unlocks it.
				local enc_lines = vim.split(encrypted, "\n", { plain = true })
				if enc_lines[#enc_lines] == "" then
					table.remove(enc_lines)
				end

				local saved_undolevels = vim.bo[bufnr].undolevels
				vim.bo[bufnr].undolevels = -1
				vim.api.nvim_buf_set_lines(bufnr, 0, -1, false, enc_lines)
				vim.bo[bufnr].undolevels = saved_undolevels

				encrypted_buffers[bufnr] = "locked"
				vim.bo[bufnr].modified = false
			end)
		end)
	end, { desc = "Encrypt and lock the buffer (shows ciphertext; :EncBufDecrypt to unlock)" })

	-- Clear tracking state when a buffer is unloaded or wiped so that
	-- reopening it triggers BufReadPost and decrypts fresh.
	vim.api.nvim_create_autocmd({ "BufUnload", "BufWipeout" }, {
		group = group,
		callback = function(ev)
			encrypted_buffers[ev.buf] = nil
		end,
	})
end

---------------------------------------------------------------------------
-- Setup
---------------------------------------------------------------------------
--- @param options? table|nil
function ENCBUF.setup(options)
	options = options or {}

	local driver_name = options.driver or "openssl"
	local driver = HELPERS.load_driver(driver_name)

	if not driver then
		vim.notify("[encbuf.nvim] Unknown driver: " .. driver_name, vim.log.levels.ERROR)
		return nil
	end
	local validated = driver.validate_options(options)
	setup_autocmds(driver, validated)
end

return ENCBUF
