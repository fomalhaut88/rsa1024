# rsa1024

RSA DLL implementation powered by Rust. 
The usage example (in Python) is provided in `dlltest.py`.

## How to build

1. `git clone https://github.com/fomalhaut88/rsa1024 --depth=1`
2. `cd rsa1024`
3. `cargo build --release`

The built DLL will be in `./target/release/`

## How to test

1. Execute Rust tests: `cargo test`
2. Run Python example: `python dlltest.py`