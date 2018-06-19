#ifndef _DY_PKCS11_H_
#define _DY_PKCS11_H_

#include "cryptoki.h"

#ifdef __cplusplus
extern "C" {
#endif

// -----------------------------------------
// DYCKK - vendor-specific key types:
// -----------------------------------------

// Advanced password key type
#define DYCKK_ADV_PASSWORD              ((unsigned)0x80007101)

// Advanced PRF key type
#define DYCKK_ADV_PRF                   ((unsigned)0x80007103)

// AES SIV key type
#define DYCKK_AES_SIV                   ((unsigned)0x80007104)

// AES XTS key type
#define DYCKK_AES_XTS                   ((unsigned)0x80007105)

// Lima key type
#define DYCKK_LIMA                      ((unsigned)0x80007107)

// -----------------------------------------
// DYCKA - vendor specific attributes:
// -----------------------------------------

// Unique identifier
#define DYCKA_UID                       ((unsigned)0x80007201)

// Password encryption EC point
#define DYCKA_PASS_EC_POINT             ((unsigned)0x80007202)

// KMIP replaced unique identifier
#define KMIP_REPLACED_UID               ((unsigned)0x80007205)

// Lima public key
#define DYCKA_LIMA_PUB_KEY              ((unsigned)0x80007207)

// -----------------------------------------
// DYCKA - vendor specific mechanisms:
// -----------------------------------------

// AES SIV
#define DYCKM_AES_SIV                   ((unsigned)0x80007e01)

// AES SIV key generation
#define DYCKM_AES_SIV_KEY_GEN           ((unsigned)0x80007e02)

// Advanced PRF
#define DYCKM_PRF                       ((unsigned)0x80007e11)

// Advanced PRF key generation
#define DYCKM_PRF_KEY_GEN               ((unsigned)0x80007e12)

// ECIES
#define DYCKM_ECIES                     ((unsigned)0x80007e13)

// Format Preserving Encryption
#define DYCKM_FPE                       ((unsigned)0x80007e14) // format preserving

// Order Preserving Encryption
#define DYCKM_OPE                       ((unsigned)0x80007e15) // order preserving

// Size Preserving Encryption
#define DYCKM_SPE                       ((unsigned)0x80007e16) // size preserving

// Advanced password encryption
#define DYCKM_PASSWORD                  ((unsigned)0x80007e21)

// Advanced password encryption key generation
#define DYCKM_PASSWORD_KEY_GEN          ((unsigned)0x80007e22)

// AES XTS
#define DYCKM_AES_XTS                   ((unsigned)0x80007e41)

// AES XTS key generation
#define DYCKM_AES_XTS_KEY_GEN           ((unsigned)0x80007e42)

// Lima
#define DYCKM_LIMA                      ((unsigned)0x80007e51)

// Lima key generation
#define DYCKM_LIMA_KEY_GEN              ((unsigned)0x80007e52)

// ----------------------------------------------
// DYCK_FPE - Format Preserving Encryption types:
// ----------------------------------------------
#define DYCK_FPE_EMAIL       1
#define DYCK_FPE_CREDIT_CARD 2
#define DYCK_FPE_US_PHONE    3
#define DYCK_FPE_SSN         4
#define DYCK_FPE_STRING      5

// Format preserving encryption mechanism parameters
typedef struct DYCK_FPE_PARAMS
{
  CK_ULONG       ulMode;          // DYCK_FPE_*
  CK_CHAR_PTR    pFormat;
  CK_ULONG       ulMaxLen;
} DYCK_FPE_PARAMS;

// Size preserving encryption mechanism parameters
typedef struct DYCK_SPE_PARAMS
{
  CK_ULONG       ulBits;          // length of data in bits
} DYCK_SPE_PARAMS;

// PRF mechanism parameters
typedef struct DYCK_PRF_PARAMS
{
  CK_ULONG      ulPurpose;
  CK_BYTE_PTR   pTweak;
  CK_ULONG      ulTweakLen;
  CK_ULONG      ulSecretLen;
} DYCK_PRF_PARAMS;

// SIV data structure
typedef struct DYCK_DATA {
  CK_BYTE_PTR pData;
  CK_ULONG    ulLen;
} DYCK_DATA;

// SIV mechanism parameters
typedef struct DYCK_AES_SIV_PARAMS {
  CK_ULONG ulAuthCount;
  DYCK_DATA* pAuthData;
} DYCK_AES_SIV_PARAMS;

#ifdef __cplusplus
} // extern "C" 
#endif

#endif // _DY_PKCS11_H_
