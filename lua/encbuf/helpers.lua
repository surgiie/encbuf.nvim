-- -------------------------------------------------------------------------
-- General helpers and support functions.
-- -------------------------------------------------------------------------
local M = {}

--- Load a driver module by name.
---
--- @param name string
--- @return table|nil
function M.load_driver(name)
	local ok, mod = pcall(require, "encbuf.drivers." .. name)
	if not ok then
		return nil
	end
	if type(mod.encrypt) ~= "function" or type(mod.decrypt) ~= "function" then
		return nil
	end
	return mod
end
--- Create a validator function that checks if a value is one of a set of allowed values.
---
--- Mostly to use with vim.validate since since it doesnt support a raw list of allowed values.
--- @param name string
--- @param values string[]
--- @param expected_type? string defaults to "string"
--- @return function
function M.one_of(name, values, expected_type)
	local set = {}
	expected_type = expected_type or "string"
	for _, v in ipairs(values) do
		set[v] = true
	end

	local allowed = table.concat(values, ", ")

	return function(v)
		if type(v) ~= expected_type then
			error(name .. " must be a " .. expected_type .. " (got " .. type(v) .. ")")
		end

		if not set[v] then
			error(("%s must be one of: %s (got '%s')"):format(name, allowed, v))
		end

		return true
	end
end
--- Run a shell command with optional stdin and return its output, or nil on error.
---
--- @param cmd string
--- @param stdin string|nil
--- @return string|nil
function M.exec(cmd, stdin)
	local result = vim.fn.system(cmd, stdin)
	if vim.v.shell_error ~= 0 then
		return nil
	end
	return result
end

return M
