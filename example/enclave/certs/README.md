# PEM-to-C Header Converter

This script "pem_to_headers.py" converts a PEM-encoded certificate or key file into a C header file that defines the PEM content as a string macro. It is useful for embedding certificates directly into C/C++ source code—particularly in environments like SGX where file system access is restricted.

## Features

- Reads a `.pem` file and generates a corresponding `.h` file.
- Escapes special characters (`\\`, `"`).
- Appends `\r\n` to each PEM line to preserve line structure.
- Generates a `#define` macro with the PEM content as a C string literal.
- Automatically adds include guards based on the output filename.
- Handles empty PEM files gracefully.

## Usage

```bash
python3 pem_to_header.py <input_file> <output_file> [--macro_name MACRO]
```

### Positional arguments
- input_file: Path to the input PEM file.
- output_file: Path to the output C header file.
- Optional arguments: --macro_name
Name of the C macro defined in the header file.
(Default: PEM_CERTIFICATE_DATA)
→ The macro will contain the escaped PEM string content. For example:

```c++
#define ROOT_CA_PEM \
"-----BEGIN CERTIFICATE-----\r\n" \
...
```

## Example

```bash
python3 pem_to_header.py ./cert.pem ./cert.h --macro_name ROOT_CA_PEM
```
Generates a header file like:

```c++
// THIS FILE IS GENERATED. DO NOT EDIT.

#ifndef CERT_H
#define CERT_H

// PEM content from: cert.pem
#define ROOT_CA_PEM \
    "-----BEGIN CERTIFICATE-----\r\n" \
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsd...xyz\r\n" \
    "-----END CERTIFICATE-----\r\n"

#endif // CERT_H
```

## Notes
You can download the official CA certificate bundle from the cURL website:

>  Mozilla's trusted certificate store: https://curl.se/ca/cacert.pem

This file contains the root certificates extracted from Mozilla's trusted certificate store, and is widely used for TLS verification in curl, libcurl, mbedtls, OpenSSL, and other TLS-enabled applications.

