#ifndef TRUSTED_CAS_PEM_DATA_H
#define TRUSTED_CAS_PEM_DATA_H

#include <stddef.h> // For size_t
#include "certs/cacert.h"

// PEM content as a C unsigned char array, initialized from concatenated string literals
const unsigned char trusted_cas_pem[] = PEM_CERTIFICATE_DATA;

// Length of the PEM data, excluding the C null terminator
const size_t trusted_cas_pem_len = sizeof(trusted_cas_pem) - 1;

#endif // TRUSTED_CAS_PEM_DATA_H
