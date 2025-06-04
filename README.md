# mbedtls-SGX: a TLS stack in SGX
## ✅ Maintained by Safeheron

> Safeheron has adopted and now actively maintains this fork of **[mbedtls-SGX](https://github.com/bl4ck5un/mbedtls-SGX)**, which was previously unmaintained. As part of its mission to support the SGX open-source ecosystem, Safeheron is advancing SGX-based TLS development with a focus on transparency and security.

### Key Enhancements by Safeheron

- **Upgraded mbedtls to [v3.6.3](https://github.com/Mbed-TLS/mbedtls/releases/tag/v3.6.3)**. Updated to the latest version to support modern TLS features, stay current with upstream security fixes, and mitigate vulnerabilities present in older versions — ensuring long-term security support.

- **Added multi-threading support**. Enclaves using mbedtls-SGX can now safely handle concurrent TLS sessions.

- **Introduced SGX-compatible time support**. Enables trusted time-based certificate validation within enclaves (e.g., checking TLS certificate expiry), which was previously unavailable due to lack of wall-clock access in SGX.

- **Rewrote the example programs**. The examples have been redesigned to be cleaner, easier to reuse, and better suited for integration, debugging, and testing.

This version brings the project up to date with current SGX and TLS best practices.

> ⚠️ For existing users of the original mbedtls-SGX, we strongly recommend migrating to this maintained version to ensure compatibility with modern SGX development practices, improved performance, and up-to-date TLS security guarantees.

---

## Overview

mbedtls-SGX is a port of [mbedtls](https://github.com/ARMmbed/mbedtls) (previously PolarSSL) to Intel-SGX. mbedtls-SGX aims to preserve **all** of the [features of mbedtls](https://tls.mbed.org/core-features). With mbedtls-SGX, you can

- use a wide array of cryptographic primitives (hash, RSA, ECC, AES, etc) in SGX.
- build SGX-secured tls clients and servers -- even OS cannot access session secrets.
- enjoy the awesome [documentation](https://tls.mbed.org/kb) and clean [API](https://tls.mbed.org/api/) of mbedtls.

In addition, mbedtls-SGX comes with [examples](https://github.com/bl4ck5un/mbedtls-SGX/tree/master/example) to help you get started. Note that certain functionality is lost due to limitations of SGX. Read on for details.

# Usage and Examples

mbedtls-SGX is a static enclave library. General steps of using mbedtls-SGX in your project are:

- compile and install mbedtls-SGX (see below)
- include `trusted/mbedtls_sgx.edl` in your enclave's EDL file.
- make sure your compiler can find the headers in `include`.
- link `libmbedtls_sgx_u.a` to the untrusted part of your application
- link `libmbedtls_sgx_t.a` to your enclave. Note that mbedtls-SGX needs to be linked in the same group with other SGX standard libs. Your Makefile (or CMakeLists.txt) needs something like

```
-Wl,--start-group  -lmbedtls_sgx_t -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group
```

## Build

```
git clone https://github.com/Safeheron/mbedtls-SGX && cd mbedtls-SGX
mkdir build && cd build
cmake ..
make -j && make install
```

Include the resultant `mbedtls_SGX-3.6.3` as part of your project.

```
mbedtls_SGX-3.6.3
├── include
│   └── mbedtls
└── lib
    ├── libmbedtls_SGX_t.a
    ├── libmbedtls_SGX_u.a
    └── mbedtls_SGX.edl

```

## Examples

To compile examples, run cmake with `-DCOMPILE_EXAMPLES=YES`

```
cmake .. -DCOMPILE_EXAMPLES=YES
make -j
```

Three examples will be built

- `c1_client`: a simple TLS client (by default it connects to `google.com:443`, dumps the HTML page and exits)
- `c2_client`: a simple TLS client (by default it connects to `localhost:4433`, dumps the HTML page and exits)
- `c2_server`: a multi-threaded TLS server, also listening at `localhost:4433` by default.

# Missing features and workarounds

Due to SGX's contraints, some features have been turned off.

- No access to file systems: mbedtls-SGX can not load CA files from file systems. To work this around, you need to hardcode root CAs as part of the enclave program. See `example/enclave/ca_bundle.h` for an example.

# License

mbedtls-SGX is open source under Apache 2.0. See LICENSE for more details.
