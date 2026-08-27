![screenshot](.md-source/image.png)
> 🌐 Read this in other languages: [English](README.md) | [Русский (Original)](README.ru.md)
# MyeKrypt (cmf)

Encryptor for files, documents and media.

I made MyeKrypt because I had nowhere to keep my passwords and wallet phrases. (Right at hand I mean)

## Build

```bash
cargo build --release
cargo install --path . --locked # optional
./target/release/cmf
# or
cmf
```

## Usage
`cmf` with no arguments opens the file directory, `./source` by default, BUT you can make your own `$MYEKRYPT_HOME`.

```bash
cmf notes.txt
cmf -d -o ~/restored notes.txt.enc
cmf -H -s ~/Documents/taxes
```

`-d` decrypts, `-o` sets the output directory, `-s` deletes the original after
encryption, `-H` binds the container to this machine.

## Keys

| Key | what it does|
| --- | --- |
| `z` | import a path and encrypt it |
| `n` | new encrypted file |
| `v` / `m` | view / edit in memory |
| `e` / `d` | encrypt / decrypt the selection |
| `x` | delete, with optional overwrite |
| `r` | reload the list |
| `i` | help |
| `q`, `Esc`, `Ctrl+C` | exit |

## Test

```bash
cargo test
```


## If you find it useful drop a star (please) (Optional)
