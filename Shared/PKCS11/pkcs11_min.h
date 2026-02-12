//
// pkcs11_min.h
// RO CEI Connector
//
// Copyright (C) 2026 Andrei-Alexandru Bleorțu
// SPDX-License-Identifier: AGPL-3.0-only
//
// Minimal PKCS#11 types/constants for dlopen usage.
// Not a full PKCS#11 header; add fields as needed.
//
// Based on PKCS#11 v2.x/v3.x conventions (unsigned long, pointers).
// This file intentionally avoids platform-specific packing.

#pragma once

#include <stdint.h>

typedef uint8_t CK_BYTE;
typedef CK_BYTE* CK_BYTE_PTR;

typedef uint8_t CK_BBOOL;

// PKCS#11 specifies CK_ULONG as "unsigned long". On 64-bit macOS this is 8 bytes.
typedef unsigned long CK_ULONG;
typedef CK_ULONG* CK_ULONG_PTR;

typedef CK_ULONG CK_RV;

typedef CK_ULONG CK_SLOT_ID;
typedef CK_SLOT_ID* CK_SLOT_ID_PTR;

typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_SESSION_HANDLE* CK_SESSION_HANDLE_PTR;

typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_OBJECT_HANDLE* CK_OBJECT_HANDLE_PTR;

typedef CK_ULONG CK_FLAGS;

typedef CK_ULONG CK_USER_TYPE;

typedef CK_ULONG CK_ATTRIBUTE_TYPE;
typedef CK_ULONG CK_OBJECT_CLASS;
typedef CK_ULONG CK_KEY_TYPE;
typedef CK_ULONG CK_MECHANISM_TYPE;

typedef CK_ULONG CK_STATE;

typedef struct CK_VERSION {
  CK_BYTE major;
  CK_BYTE minor;
} CK_VERSION;

typedef struct CK_TOKEN_INFO {
  CK_BYTE label[32];
  CK_BYTE manufacturerID[32];
  CK_BYTE model[16];
  CK_BYTE serialNumber[16];
  CK_FLAGS flags;
  CK_ULONG ulMaxSessionCount;
  CK_ULONG ulSessionCount;
  CK_ULONG ulMaxRwSessionCount;
  CK_ULONG ulRwSessionCount;
  CK_ULONG ulMaxPinLen;
  CK_ULONG ulMinPinLen;
  CK_ULONG ulTotalPublicMemory;
  CK_ULONG ulFreePublicMemory;
  CK_ULONG ulTotalPrivateMemory;
  CK_ULONG ulFreePrivateMemory;
  CK_VERSION hardwareVersion;
  CK_VERSION firmwareVersion;
  CK_BYTE utcTime[16];
} CK_TOKEN_INFO;

typedef struct CK_SESSION_INFO {
  CK_SLOT_ID slotID;
  CK_STATE state;
  CK_FLAGS flags;
  CK_ULONG ulDeviceError;
} CK_SESSION_INFO;

typedef struct CK_MECHANISM {
  CK_MECHANISM_TYPE mechanism;
  void* pParameter;
  CK_ULONG ulParameterLen;
} CK_MECHANISM;

typedef CK_TOKEN_INFO* CK_TOKEN_INFO_PTR;
typedef CK_MECHANISM* CK_MECHANISM_PTR;

typedef struct CK_ATTRIBUTE {
  CK_ATTRIBUTE_TYPE type;
  void* pValue;
  CK_ULONG ulValueLen;
} CK_ATTRIBUTE;

typedef CK_ATTRIBUTE* CK_ATTRIBUTE_PTR;

// Common return values
#define CKR_OK 0x00000000u
#define CKR_GENERAL_ERROR 0x00000005u
#define CKR_ARGUMENTS_BAD 0x00000007u
#define CKR_CRYPTOKI_NOT_INITIALIZED 0x00000190u
#define CKR_CRYPTOKI_ALREADY_INITIALIZED 0x00000191u
#define CKR_TOKEN_NOT_PRESENT 0x000000E0u
#define CKR_PIN_INCORRECT 0x000000A0u
#define CKR_PIN_LOCKED 0x000000A4u
#define CKR_USER_ALREADY_LOGGED_IN 0x00000100u
#define CKR_USER_NOT_LOGGED_IN 0x00000101u
#define CKR_USER_PIN_NOT_INITIALIZED 0x00000102u
#define CKR_SESSION_HANDLE_INVALID 0x000000B3u

// Special values
// CK_UNAVAILABLE_INFORMATION signals "attribute not available" when returned in
// CK_ATTRIBUTE.ulValueLen by C_GetAttributeValue.
// Must be CK_ULONG-width to match 64-bit platforms where CK_ULONG is 8 bytes.
#define CK_UNAVAILABLE_INFORMATION ((CK_ULONG)-1)

// User types
#define CKU_SO 0u
#define CKU_USER 1u

// Session flags
#define CKF_SERIAL_SESSION 0x00000004u
#define CKF_RW_SESSION 0x00000002u

// Token flags (for CK_TOKEN_INFO.flags)
#define CKF_USER_PIN_LOCKED 0x00080000u
#define CKF_USER_PIN_FINAL_TRY 0x00100000u

// Object classes
#define CKO_DATA 0x00000000u
#define CKO_CERTIFICATE 0x00000001u
#define CKO_PUBLIC_KEY 0x00000002u
#define CKO_PRIVATE_KEY 0x00000003u
#define CKO_SECRET_KEY 0x00000004u

// Certificate types
#define CKC_X_509 0x00000000u

// Attributes
#define CKA_CLASS 0x00000000u
#define CKA_TOKEN 0x00000001u
#define CKA_PRIVATE 0x00000002u
#define CKA_LABEL 0x00000003u
#define CKA_VALUE 0x00000011u
#define CKA_CERTIFICATE_TYPE 0x00000080u
#define CKA_ID 0x00000102u
#define CKA_KEY_TYPE 0x00000100u
#define CKA_EC_PARAMS 0x00000180u
#define CKA_EC_POINT 0x00000181u

typedef struct CK_MECHANISM_INFO {
  CK_ULONG ulMinKeySize;
  CK_ULONG ulMaxKeySize;
  CK_FLAGS flags;
} CK_MECHANISM_INFO;
typedef CK_MECHANISM_INFO* CK_MECHANISM_INFO_PTR;

typedef CK_MECHANISM_TYPE* CK_MECHANISM_TYPE_PTR;

// ECDH key derivation
typedef CK_ULONG CK_EC_KDF_TYPE;
#define CKD_NULL             0x00000001u  // No KDF — raw Z value (X coordinate)

typedef struct CK_ECDH1_DERIVE_PARAMS {
  CK_EC_KDF_TYPE  kdf;               // Key derivation function (CKD_NULL for raw)
  CK_ULONG        ulSharedDataLen;   // Length of optional shared data
  CK_BYTE_PTR     pSharedData;       // Optional shared data (NULL for CKD_NULL)
  CK_ULONG        ulPublicDataLen;   // Length of other party's EC public key
  CK_BYTE_PTR     pPublicData;       // Other party's uncompressed EC point (04 || X || Y)
} CK_ECDH1_DERIVE_PARAMS;
typedef CK_ECDH1_DERIVE_PARAMS* CK_ECDH1_DERIVE_PARAMS_PTR;

// Key type for derived secret
#define CKK_GENERIC_SECRET   0x00000010u

// Additional attributes needed for C_DeriveKey template
#define CKA_SENSITIVE        0x00000103u
#define CKA_EXTRACTABLE      0x00000162u
#define CKA_VALUE_LEN        0x00000161u

// Boolean values
#define CK_TRUE  ((CK_BBOOL)1)
#define CK_FALSE ((CK_BBOOL)0)

// Mechanisms
#define CKM_EC_KEY_PAIR_GEN           0x00001040u
#define CKM_ECDSA                     0x00001041u
#define CKM_ECDSA_SHA1                0x00001042u
#define CKM_ECDSA_SHA256              0x00001044u
#define CKM_ECDSA_SHA384              0x00001045u
#define CKM_ECDSA_SHA512              0x00001046u
#define CKM_ECDH1_DERIVE              0x00001050u
#define CKM_ECDH1_COFACTOR_DERIVE     0x00001051u

// Mechanism info flags
#define CKF_DERIVE                    0x00080000u

// Note: We don't use CK_FUNCTION_LIST because IDEMIA's library has non-standard offsets.
// Function pointer typedefs (PFN_C_*) are defined in PKCS11.h for direct dlsym() resolution.
