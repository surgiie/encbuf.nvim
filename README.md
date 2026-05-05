# encbuf.nvim

Transparent encryption for Neovim buffers.

## Requirements

- Neovim 0.10+
- A supported driver (see below)

## Installation

**lazy.nvim**
```lua
{
  "surgiie/encbuf.nvim",
  config = function()
    require("encbuf").setup()
  end,
}
```

**packer.nvim**
```lua
use {
  "surgiie/encbuf.nvim",
  config = function()
    require("encbuf").setup()
  end,
}
```

## Supported drivers

- `openssl` — uses the `openssl enc` command-line tool (default)

## Commands

| Command | Description |
|---|---|
| `:EncBufDecrypt` | Decrypt the current buffer from disk (also unlocks a locked buffer) |
| `:EncBufEncrypt` | Encrypt and lock the buffer — replaces buffer content with ciphertext so you can confirm the file is encrypted. Use `:EncBufDecrypt` to unlock and resume editing. |

Normal saves (`:w`) use transparent mode: the file is encrypted on disk and the buffer stays as plaintext.

## Configuration

All options are passed to `setup()`. Options not specified fall back to the driver's defaults.

```lua
require("encbuf").setup({
  driver = "openssl",           -- which driver to use

  -- Patterns of files that are treated as encrypted.
  -- Driver defaults *.enc and *.enc.* are always included; these are appended.
  file_patterns = {},

  -- Automatically decrypt matching files when opened.
  auto_decrypt_on_open = true,
})
```

---

## Drivers

### `openssl`

Uses `openssl enc` for symmetric encryption. Requires `openssl` on `$PATH`.

Supports two encryption methods selected by `encryption_method`:

- **`"key"`** — raw key/IV provided directly (`-K`/`-iv` flags). No key derivation.
- **`"passphrase"`** — passphrase-based key derivation via PBKDF2.

#### Full option reference

```lua
require("encbuf").setup({
  driver = "openssl",

  -- Symmetric cipher. Supported: "aes-256-cbc", "aes-256-ctr", "chacha20"
  cipher = "aes-256-cbc",

  -- "key"        raw key/IV (no key derivation)
  -- "passphrase" PBKDF2-derived key from a passphrase
  encryption_method = "key",

  -- Encode ciphertext as base64 so the file is plain-text safe.
  base64 = true,

  -- Prepend a salt header (only applies to the "passphrase" method;
  -- ignored for "key" since there is no key derivation step).
  salt = true,

  -- File patterns treated as encrypted (driver defaults always included).
  file_patterns = { "*.enc", "*.enc.*" },

  -- Decrypt automatically when a matching file is opened.
  auto_decrypt_on_open = true,

  -- -------------------------------------------------------------------------
  -- "key" method options
  -- -------------------------------------------------------------------------
  key = {
    -- Where to read the key and IV from.
    -- "env"    read from environment variables (default)
    -- "prompt" prompt the user interactively
    source = "env",

    -- Environment variable names (used when source = "env").
    key_env_var = "ENCBUF_OPENSSL_KEY",
    iv_env_var  = "ENCBUF_OPENSSL_IV",

    -- Encoding of the key/IV values.
    -- "hex"    lowercase or uppercase hex string (default)
    -- "base64" standard base64 string
    encoding = "hex",
  },

  -- -------------------------------------------------------------------------
  -- "passphrase" method options
  -- -------------------------------------------------------------------------
  passphrase = {
    -- Where to read the passphrase from.
    -- "prompt" prompt the user interactively (default)
    -- "env"    read from an environment variable
    source = "prompt",

    -- Environment variable name (used when source = "env").
    env_var = "ENCBUF_OPENSSL_PASSPHRASE",

    -- Ask for the passphrase twice on first encrypt of a new file.
    confirm = true,

    -- Cache the passphrase in memory for the Neovim session.
    cache = true,

    -- How long (seconds) to keep the passphrase cached.
    cache_timeout = 300,
  },

  -- PBKDF2 key derivation settings (passphrase method only).
  pbkdf2 = {
    iterations = 100000,
    digest     = "sha256",
  },

  -- -------------------------------------------------------------------------
  -- openssl binary options
  -- -------------------------------------------------------------------------
  openssl = {
    -- Path or name of the openssl binary.
    bin = "openssl",

    -- Extra arguments appended to every openssl enc invocation.
    extra_args = {},
  },
})
```

#### Security notes

- The passphrase is passed to openssl via stdin (`-pass stdin`), never as a command-line argument, so it does not appear in `ps` or `/proc/<pid>/cmdline`.
- Raw key/IV values (`key` method) are read from environment variables or a prompt and passed as `-K`/`-iv` arguments. Keep environment variables out of shell history and process listings.
- `undofile`, `swapfile` are disabled for every encrypted buffer to prevent plaintext leaking to disk through Neovim's own file-writing mechanisms.
