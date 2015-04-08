/*++
Copyright (c) 2013  Microsoft Corporation

Module Name:

    xCryptLib.h

Abstract:

    This is the header file for the Microsoft XCG portable Cryptography Library.

Author:

    Dan Shumow (danshu)     Jun 2013
    Jason Mackay (jmackay)  
    Greg Zaverucha (gregz)  Jul 2013
    Tolga Acar (tolga)      Sep 2013

Revision History:

    Yannis Rouselakis (yarou) May 2014: Adding MD5 and RC4 support

--*/

/// @file xCryptLib.h
/// xCryptLib API header file.
/// xCryptLib is a cross-platform cryptography library. 
/// 

///
///    \mainpage 
///    \section introduction Introduction
///    \par
///    xCryptLib is a cross-platform cryptography library developed by the XCG Security and Cryptography Group.
///    The library is designed to compile and run on non-Microsoft platforms such as iOS, Android and OSX.
///    Because it has no external dependencies, it is also suitable for use in embedded or isolated environments.
///
///    \subsection apiref API Reference
///    \par
///    <b>The API is documented in \ref xCryptLib.h</b>
///    All functions in \ref xCryptLib.h are part of the xCrypt API, even those that are not documented here.
///
/// \subsection build Building xCryptLib
///
/// xCryptLib is kept in the BigTop depot, in //depot/Partners/xCryptLib/....  The
/// file xCryptLibEnlist.zip has scripts to setup and enlistment and get the code.
///
/// The main xCrypt library (xCryptLib) has two dependencies
/// - xCryptSymmetric, providing symmetric key primitives (AES, SHA, ...), and
/// - xCryptAsymmetirc, providing asymmetric key primitives (RSA, ECDSA, ...)
///
/// These two sub-libraries are in the Enigma depot, because they contain all the
/// export-controlled crypto.  They are both built from source files that belong to
/// other projects (rsa32.lib and msbignum.lib, respectively).
///
/// Enigma paths:
///  - enigma\\released\\windows\\bignum\\xCryptAsymmetric
///  - enigma\\released\\windows\\ntrsa32\\xCryptSymmetric
///
/// Once you have all of these synched up, there are build scripts in xCryptLib
/// root:
///    - FullBuild_Win.bat, Builds for Windows x86/x64/Phone/RT
///    - FullBuild_Android.bat, Build for Android with the NDK
///    - Build_iOS.sh, build for iOS on a Mac with XCode.
///      xCryptLib\\xCryptLib.xcworkspace is an XCode workspace
/// They will build all three xCrypt projects, and copy the binaries & headers from
/// xCryptSymmetric and xCryptAsymmetric to xCryptLib\\external
///
/// \subsection using Using xCryptLib
/// To use xCryptLib, you'll need to \#include xCryptLib.h, which defines the xCrypt
/// API. The test project, xCryptTest has samples, and documentation is in
/// xCryptLib\\docs\\html.  The documentation is not 100% complete, so be aware that
/// there may be functions in xCryptLib.h which are not documented, but still
/// part of the xCrypt API and may be used.
///
///
///
///     \defgroup AES  AES API Functions
///     \defgroup ECC  Elliptic Curve Cryptography API Functions
///     \defgroup HMAC HMAC API Functions
///     \defgroup KDF  Key Derivation (KDF) API Functions
///     \defgroup HASH Hashing API Functions
///     \defgroup CB   User-Provided Callbacks
///     \defgroup RSA  RSA Functions
// TODO: Assign functions to groups.  The AES ones are done. (gregz)


#include "sal.h"
#include "port.h"

#ifndef __XCRYPTLIB_H__
#define __XCRYPTLIB_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifndef XCRYPTLIBAPI
  #define XCRYPTLIBAPI
#endif

typedef unsigned long   CRYPTO_RESULT;

#define CRYPTO_SUCCESS                      (0x00000000)
#define CRYPTO_ERROR_NO_MEMORY              (0x00000001)
#define CRYPTO_ERROR_INVALID_PARAMETER      (0x00000002)
#define CRYPTO_ERROR_SIGNATURE_CHECK_FAILED (0x00000003)
#define CRYPTO_ERROR_UNKNOWN                (0x00000004)
#define CRYPTO_ERROR_BUFFER_TOO_SMALL       (0x00000005)
#define CRYPTO_ERROR_NOT_IMPLEMENTED        (0x00000006)
#define CRYPTO_ERROR_DECRYPTION_FAILED      (0x00000007)
#define CRYPTO_ERROR_ENCRYPTION_FAILED      (0x00000008)

typedef long CRYPTO_BOOL;

#define CRYPTO_FALSE    (0x00000000)
#define CRYPTO_TRUE     (0xffffffff)
// END TODO: MERGE WITH rsa_verify.h

#define XCRYPTLIBBUFFER_VERSION (0x00000001)

typedef struct _xCryptLibParamBuffer {
    size_t          cbBuffer;
    const wchar_t*  pwszBufferType;
    const void*     pvBuffer;
} xCryptLibParamBuffer, *PxCryptLibParamBuffer;

typedef struct _xCryptLibParamList {
    unsigned long           ulVersion;
    size_t                  cBuffers;
    PxCryptLibParamBuffer   pBuffers;
} xCryptLibParamList;

typedef const xCryptLibParamList* PxCryptLibParamList;

/// NULL parameter list macro for readability.
#define NULL_PARAMLIST NULL

/// Parameter to provide the name of function (a hash function or HMAC) to use with a KDF. \ingroup KDF
#define XCRYPTLIB_PARAM_NAME_KDF_HASH_FUNCTION  L"xCryptLibParamKDFHashFunction"
/// Parameter to set the key to be used with an instance of HMAC. \ingroup HMAC 
#define XCRYPTLIB_PARAM_NAME_HMAC_KEY           L"xCryptLibParamHMACKey" 
/// Parameter to provided additional data to be included in a KDF, before the secret data. \ingroup KDF
#define XCRYPTLIB_PARAM_NAME_KDF_SECRET_APPEND  L"xCryptLibParamKDFSecretAppend"
/// Parameter to provided additional data to be included in a KDF, after the secret data. \ingroup KDF
#define XCRYPTLIB_PARAM_NAME_KDF_SECRET_PREPEND L"xCryptLibParamKDFSecretPrepend"
/// Parameter to provided label to be included in the SP800-108 KDF. \ingroup KDF
#define XCRYPTLIB_PARAM_NAME_KDF_SP800_108_LABEL L"xCryptLibParamKDFSP800-108Label"
/// Parameter to provided context to be included in the SP800-108 KDF. \ingroup KDF
#define XCRYPTLIB_PARAM_NAME_KDF_SP800_108_CONTEXT L"xCryptLibParamKDFSP800-108Context"
/// Parameter to pass flags to a function.
#define XCRYPTLIB_PARAM_NAME_FLAGS              L"xCryptLibParamFlags"
/// Parameter to set an elliptic curve by name. \ingroup ECC
#define XCRYPTLIB_PARAM_NAME_CURVE_NAME         L"xCryptLibParamCurveName"
/// Parameter to specify label for RSA OAEP. \ingroup RSA
#define XCRYPTLIB_PARAM_NAME_RSA_OAEP_LABEL     L"xCryptLibParamRsaOaepLabel"
/// Parameter to specify salt for RSA OAEP. \ingroup RSA
#define XCRYPTLIB_PARAM_NAME_RSA_OAEP_SALT     L"xCryptLibParamRsaOaepSalt"
/// Flag to have HMAC-based KDFs use the secret as the HMAC key  \ingroup KDF
#define XCRYPTLIB_KDF_USE_SECRET_AS_HMAC_KEY_FLAG (0x1)
/// Flag to set the behavior of ECDSA signing when the input digest is longer than the group order.
/// When the flag is used, ECSDA sign and verify will truncate the digest to the length of the group
/// order (following CNG and SEC1).  When the flag is not set, the digest is reduced modulo the group
/// order. \ingroup ECC
#define XCRYPTLIB_ECDSA_HASH_TRUNCATE_FLAG (0x2)
/// Flag to use the SP800-108 KDF \ingroup KDF
#define XCRYPTLIB_KDF_SP800_108_FLAG (0x4)


/*  
 *  Hash/HMAC function names.  For example, these are valid parameter names 
 *  of type XCRYPTLIB_PARAM_NAME_KDF_HASH_FUNCTION.
*/
/// String to identify the hash function SHA-256 \ingroup HASH
#define XCRYPT_HASH_NAME_SHA256 L"xCryptHashNameSHA256"
/// String to identify the function HMAC-SHA-256  \ingroup HASH
#define XCRYPT_HASH_NAME_HMAC_SHA256 L"xCryptHashNameHMACSHA256"
/// String to identify the hash function SHA-384  \ingroup HASH
#define XCRYPT_HASH_NAME_SHA384 L"xCryptHashNameSHA384"
/// String to identify the function HMAC-SHA-256  \ingroup HASH
#define XCRYPT_HASH_NAME_HMAC_SHA384 L"xCryptHashNameHMACSHA384"
/// String to identify the hash function SHA-512  \ingroup HASH
#define XCRYPT_HASH_NAME_SHA512 L"xCryptHashNameSHA512"
/// String to identify the hash function HMAC-SHA-512  \ingroup HASH
#define XCRYPT_HASH_NAME_HMAC_SHA512 L"xCryptHashNameHMACSHA512"
/// String to identify the hash function MD5  \ingroup HASH
#define XCRYPT_HASH_NAME_MD5 L"xCryptHashNameMD5"


/*
 *
 *  Hash Functionality
 *
 */

#ifndef SHA1_DIGEST_LEN
    #define SHA1_DIGEST_LEN      (20)
#endif
#ifndef SHA256_DIGEST_LEN               
    #define SHA256_DIGEST_LEN    (32)
#endif
#ifndef SHA384_DIGEST_LEN
    #define SHA384_DIGEST_LEN    (48)      
#endif
#ifndef SHA512_DIGEST_LEN
    #define SHA512_DIGEST_LEN    (64)
#endif
#ifndef MD5_DIGEST_LEN
    #define MD5_DIGEST_LEN       (16)
#endif

struct _SHA1_HASH;
typedef struct _SHA1_HASH* PSHA1_HASH;

struct _SHA256_HASH;
typedef struct _SHA256_HASH* PSHA256_HASH;

struct _SHA384_HASH;
typedef struct _SHA384_HASH* PSHA384_HASH;

struct _SHA512_HASH;
typedef struct _SHA512_HASH* PSHA512_HASH;

struct _MD5_HASH;
typedef struct _MD5_HASH* PMD5_HASH;

// Hash function pointer type.

/// <summary>Hash function pointer type.</summary>
/// <remarks>
/// The goal of this API is to create an easy-to-use combined algorithms such
/// as digital signature with appendix. 
/// This type is typically used in asymmetric cryptography APIs
/// such as RSA-PKCS#1v1.5 digital signature verification.
/// The caller may use the built-in hash functions, or any other externally-provided hash function.
/// </remarks>
/// <seealso cref="xCryptLibRsaPkcs1VerifySignature"/>
/// <seealso cref="xCryptLibSha1Hash"/>
/// <seealso cref="xCryptLibSha256Hash"/>
/// <seealso cref="xCryptLibSha384Hash"/>
/// <seealso cref="xCryptLibSha512Hash"/>
/// \ingroup HASH
typedef CRYPTO_RESULT (*xCryptHashFn_t)(
    __in_bcount(cbIn) unsigned char         *pbIn,
    size_t                                  cbIn,
    __out_bcount_full(cbOut) unsigned char  *pbOut,
    size_t                                  cbOut);

//
// The following hash functions are implemented in xCryptLib for convenience.
// Any other implementation can also be used.
//

/// <summary>Compute the SHA-1 digest of the message.</summary>
/// <param name="pbIn">Pointer to the input message. </param>
/// <param name="cbIn">Length of input message in number in bytes.</param>
/// <param name="pbOut">Pointer to the output memory to write the computed message digest to.</param>
/// <param name="cbOut">Length of the output memory in bytes.</param>
/// <remarks>The hash (message digest) output is computed over the input bytes in one step,
/// and is written to the output memory.
/// The caller must ensure that the output memory length is exactly the same as the hash function output
/// length <see cref="SHA1_DIGEST_LEN"/> and that the output buffer does not violate the alignment requirements per architecture.
/// </remarks>
/// <seealso cref="SHA1_DIGEST_LEN"/>
/// <seealso cref="xCryptHashFn_t"/>
/// \ingroup HASH
CRYPTO_RESULT
xCryptSha1Hash(
    __in_bcount(cbIn)           unsigned char   *pbIn,
                                size_t          cbIn,
    __out_bcount_full(cbOut)    unsigned char   *pbOut,
                                size_t          cbOut);

/// <summary>Compute the SHA-256 digest of the message.</summary>
/// <param name="pbIn">Pointer to the input message. </param>
/// <param name="cbIn">Length of input message in number in bytes.</param>
/// <param name="pbOut">Pointer to the output memory to write the computed message digest to.</param>
/// <param name="cbOut">Length of the output memory in bytes.</param>
/// <remarks>The hash (message digest) output is computed over the input bytes in one step,
/// and is written to the output memory.
/// The caller must ensure that the output memory length is exactly the same as the hash function output
/// length <see cref="SHA256_DIGEST_LEN"/> and that the output buffer does not violate the alignment requirements per architecture.  
/// The parameters <paramref name="pbIn"/> and <paramref name="pbOut"/> may overlap.
/// </remarks>
/// <seealso cref="SHA256_DIGEST_LEN"/>
/// <seealso cref="xCryptHashFn_t"/>
/// \ingroup HASH
CRYPTO_RESULT
xCryptSha256Hash(
    __in_bcount(cbIn)           unsigned char   *pbIn,
                                size_t          cbIn,
    __out_bcount_full(cbOut)    unsigned char   *pbOut,
                                size_t          cbOut);

/// <summary>Compute the SHA-384 digest of the message.</summary>
/// <param name="pbIn">Pointer to the input message. </param>
/// <param name="cbIn">Length of input message in number in bytes.</param>
/// <param name="pbOut">Pointer to the output memory to write the computed message digest to.</param>
/// <param name="cbOut">Length of the output memory in bytes.</param>
/// <remarks>The hash (message digest) output is computed over the input bytes in one step,
/// and is written to the output memory.
/// The caller must ensure that the output memory length is exactly the same as the hash function output
/// length <see cref="SHA384_DIGEST_LEN"/> and that the output buffer does not violate the alignment requirements per architecture.
/// </remarks>
/// <seealso cref="SHA384_DIGEST_LEN"/>
/// <seealso cref="xCryptHashFn_t"/>
/// \ingroup HASH
CRYPTO_RESULT
xCryptSha384Hash(
    __in_bcount(cbIn)           unsigned char   *pbIn,
                                size_t          cbIn,
    __out_bcount_full(cbOut)    unsigned char   *pbOut,
                                size_t          cbOut);

/// <summary>Compute the SHA-512 digest of the message.</summary>
/// <param name="pbIn">Pointer to the input message. </param>
/// <param name="cbIn">Length of input message in number in bytes.</param>
/// <param name="pbOut">Pointer to the output memory to write the computed message digest to.</param>
/// <param name="cbOut">Length of the output memory in bytes.</param>
/// <remarks>The hash (message digest) output is computed over the input bytes in one step,
/// and is written to the output memory.
/// The caller must ensure that the output memory length is exactly the same as the hash function output
/// length <see cref="SHA512_DIGEST_LEN"/> and that the output buffer does not violate the alignment requirements per architecture.
/// </remarks>
/// <seealso cref="SHA512_DIGEST_LEN"/>
/// <seealso cref="xCryptHashFn_t"/>
/// \ingroup HASH
CRYPTO_RESULT
xCryptSha512Hash(
    __in_bcount(cbIn)           unsigned char   *pbIn,
                                size_t          cbIn,
    __out_bcount_full(cbOut)    unsigned char   *pbOut,
                                size_t          cbOut);

/// <summary>Compute the MD5 digest of the message.</summary>
/// <param name="pbIn">Pointer to the input message. </param>
/// <param name="cbIn">Length of input message in number in bytes.</param>
/// <param name="pbOut">Pointer to the output memory to write the computed message digest to.</param>
/// <param name="cbOut">Length of the output memory in bytes.</param>
/// <remarks>The hash (message digest) output is computed over the input bytes in one step,
/// and is written to the output memory.
/// The caller must ensure that the output memory length is exactly the same as the hash function output
/// length <see cref="MD5_DIGEST_LEN"/> and that the output buffer does not violate the alignment requirements per architecture.
/// </remarks>
/// <seealso cref="MD5_DIGEST_LEN"/>
/// <seealso cref="xCryptHashFn_t"/>
/// \ingroup HASH
CRYPTO_RESULT
xCryptMD5Hash(
__in_bcount(cbIn)           unsigned char   *pbIn,
size_t          cbIn,
__out_bcount_full(cbOut)    unsigned char   *pbOut,
size_t          cbOut);

size_t
XCRYPTLIBAPI
xCryptLibGetSha1HashObjectSize();

PSHA1_HASH
XCRYPTLIBAPI
xCryptLibAllocateSha1Hash(
    void*   pvBufferForHash,
    size_t  cbBufferForHash);

void
XCRYPTLIBAPI
xCryptLibFreeSha1Hash(
    PSHA1_HASH  pHash);

void
XCRYPTLIBAPI
xCryptLibInitializeSha1Hash(
    PSHA1_HASH   pHash);

void
XCRYPTLIBAPI
xCryptLibUpdateSha1Hash(
    PSHA1_HASH              pHash,
    const unsigned char*    pbToHash,
    size_t                  cbToHash);

void
XCRYPTLIBAPI
xCryptLibFinishSha1Hash(
    PSHA1_HASH      pHash,
    unsigned char   rgbDigest[SHA1_DIGEST_LEN]); 

/// <summary> Get the size, in bytes, of a SHA-256 object. </summary>
/// <returns> The number of bytes required to store a SHA-256 object.</returns>
/// <remarks>
///  The SHA-256 object type is <see cref="PSHA256_HASH"/>
/// </remarks>
/// \ingroup HASH
size_t
XCRYPTLIBAPI
xCryptLibGetSha256HashObjectSize();

/// <summary> Create a SHA-256 object. </summary>
/// <param name="pvBufferForHash"> Buffer to store the hash object </param>
/// <param name="cbBufferForHash"> Size in bytes of <paramref name="pvBufferForHash"/>. </param>
/// <returns> A new SHA-256 object, or <c>NULL</c> on error.</returns>
/// <remarks>
/// The size of <paramref name="pvBufferForHash"/> must be at least as large as the number of
///  bytes returned by <see cref="xCryptLibGetSha256HashObjectSize"/>.
/// </remarks>
/// \ingroup HASH
PSHA256_HASH
XCRYPTLIBAPI
xCryptLibAllocateSha256Hash(
    void*   pvBufferForHash,
    size_t  cbBufferForHash);

void
XCRYPTLIBAPI
xCryptLibFreeSha256Hash(
    PSHA256_HASH  pHash);

void
XCRYPTLIBAPI
xCryptLibInitializeSha256Hash(
    PSHA256_HASH   pHash);

void
XCRYPTLIBAPI
xCryptLibUpdateSha256Hash(
    PSHA256_HASH            pHash,
    const unsigned char*    pbToHash,
    size_t                  cbToHash);

void
XCRYPTLIBAPI
xCryptLibFinishSha256Hash(
    PSHA256_HASH    pHash,
    unsigned char   rgbDigest[SHA256_DIGEST_LEN]); 


size_t
XCRYPTLIBAPI
xCryptLibGetSha384HashObjectSize();

PSHA384_HASH
XCRYPTLIBAPI
xCryptLibAllocateSha384Hash(
    void*   pvBufferForHash,
    size_t  cbBufferForHash);

void
XCRYPTLIBAPI
xCryptLibFreeSha384Hash(
    PSHA384_HASH  pHash);

void
XCRYPTLIBAPI
xCryptLibInitializeSha384Hash(
    PSHA384_HASH   pHash);

void
XCRYPTLIBAPI
xCryptLibUpdateSha384Hash(
    PSHA384_HASH            pHash,
    const unsigned char*    pbToHash,
    size_t                  cbToHash);

void
XCRYPTLIBAPI
xCryptLibFinishSha384Hash(
    PSHA384_HASH    pHash,
    unsigned char   rgbDigest[SHA384_DIGEST_LEN]); 

size_t
XCRYPTLIBAPI
xCryptLibGetSha512HashObjectSize();

PSHA512_HASH
XCRYPTLIBAPI
xCryptLibAllocateSha512Hash(
    void*   pvBufferForHash,
    size_t  cbBufferForHash);

void
XCRYPTLIBAPI
xCryptLibFreeSha512Hash(
    PSHA512_HASH    pHash);

void
XCRYPTLIBAPI
xCryptLibInitializeSha512Hash(
    PSHA512_HASH    pHash);

void
XCRYPTLIBAPI
xCryptLibUpdateSha512Hash(
    PSHA512_HASH            pHash,
    const unsigned char*    pbToHash,
    size_t                  cbToHash);

void
XCRYPTLIBAPI
xCryptLibFinishSha512Hash(
    PSHA512_HASH    pHash,
    unsigned char   rgbDigest[SHA512_DIGEST_LEN]);

size_t
XCRYPTLIBAPI
xCryptLibGetMd5HashObjectSize();

PMD5_HASH
XCRYPTLIBAPI
xCryptLibAllocateMd5Hash(
    void*   pvBufferForHash,
    size_t  cbBufferForHash);

void
XCRYPTLIBAPI
xCryptLibFreeMd5Hash(
    PMD5_HASH  pHash);

void
XCRYPTLIBAPI
xCryptLibInitializeMd5Hash(
    PMD5_HASH   pHash);

void
XCRYPTLIBAPI
xCryptLibUpdateMd5Hash(
    PMD5_HASH              pHash,
    const unsigned char*    pbToHash,
    size_t                  cbToHash);

void
XCRYPTLIBAPI
xCryptLibFinishMd5Hash(
    PMD5_HASH      pHash,
    unsigned char   rgbDigest[MD5_DIGEST_LEN]);

/*
* HMAC Functionality
*/

struct _SHA256_HMAC;
typedef struct _SHA256_HMAC* PSHA256_HMAC;

struct _SHA384_HMAC;
typedef struct _SHA384_HMAC* PSHA384_HMAC;

struct _SHA512_HMAC;
typedef struct _SHA512_HMAC* PSHA512_HMAC;

size_t
XCRYPTLIBAPI
xCryptLibGetSha256HmacObjectSize();

PSHA256_HMAC
XCRYPTLIBAPI
xCryptLibAllocateSha256Hmac(
    void*   pvBufferForHmac,
    size_t  cbBufferForHmac);

void
XCRYPTLIBAPI
xCryptLibFreeSha256Hmac(
    PSHA256_HMAC    pHmac);

void
XCRYPTLIBAPI
xCryptLibInitializeSha256Hmac(
    PSHA256_HMAC            pHmac,
    const unsigned char*    pbKey,
    size_t                  cbKey);

void
XCRYPTLIBAPI
xCryptLibUpdateSha256Hmac(
    PSHA256_HMAC            pHmac,
    const unsigned char*    pbToMAC,
    size_t                  cbToMAC);

void
XCRYPTLIBAPI
xCryptLibFinishSha256Hmac(
    PSHA256_HMAC    pHmac,
    unsigned char   rgbDigest[SHA256_DIGEST_LEN]); 

size_t
XCRYPTLIBAPI
xCryptLibGetSha384HmacObjectSize();

PSHA384_HMAC
XCRYPTLIBAPI
xCryptLibAllocateSha384Hmac(
    void*   pvBufferForHmac,
    size_t  cbBufferForHmac);

void
XCRYPTLIBAPI
xCryptLibFreeSha384Hmac(
    PSHA384_HMAC    pHmac);

void
XCRYPTLIBAPI
xCryptLibInitializeSha384Hmac(
    PSHA384_HMAC            pHmac,
    const unsigned char*    pbKey,
    size_t                  cbKey);

void
XCRYPTLIBAPI
xCryptLibUpdateSha384Hmac(
    PSHA384_HMAC            pHmac,
    const unsigned char*    pbToMAC,
    size_t                  cbToMAC);

void
XCRYPTLIBAPI
xCryptLibFinishSha384Hmac(
    PSHA384_HMAC    pHmac,
    unsigned char   rgbDigest[SHA384_DIGEST_LEN]); 

size_t
XCRYPTLIBAPI
xCryptLibGetSha512HmacObjectSize();

PSHA512_HMAC
XCRYPTLIBAPI
xCryptLibAllocateSha512Hmac(
    void*   pvBufferForHmac,
    size_t  cbBufferForHmac);

void
XCRYPTLIBAPI
xCryptLibFreeSha512Hmac(
    PSHA512_HMAC    pHmac);

void
XCRYPTLIBAPI
xCryptLibInitializeSha512Hmac(
    PSHA512_HMAC            pHmac,
    const unsigned char*    pbKey,
    size_t                  cbKey);

void
XCRYPTLIBAPI
xCryptLibUpdateSha512Hmac(
    PSHA512_HMAC            pHmac,
    const unsigned char*    pbToMAC,
    size_t                  cbToMAC);

void
XCRYPTLIBAPI
xCryptLibFinishSha512Hmac(
    PSHA512_HMAC    pHmac,
    unsigned char   rgbDigest[SHA512_DIGEST_LEN]);

/*
 * RC4 Functionality
 */

struct _XRC4_KEY;
/// Pointer to an RC4 context object (opaque). \ingroup RC4
typedef struct _XRC4_KEY* PXRC4_KEY;

/// <summary> Allocate an RC4 key. </summary>
/// <param name="pParamList"> List of parameters.  Must be <c>NULL</c> or empty. </param>
/// <returns> An allocated key, or <c>NULL</c>. </returns>
/// <see cref="xCryptLibFreeRC4Key"/>
/// \ingroup RC4
PXRC4_KEY
XCRYPTLIBAPI
xCryptLibAllocateRC4Key(PxCryptLibParamList pParamList);

/// <summary> Free an allocated RC4 key. </summary>
/// <param name="key"> The key to be freed.  Must be non-<c>NULL</c></param>
/// <remarks>
///   Zeroes the key material from memory.
/// </remarks>
/// \ingroup RC4
void
XCRYPTLIBAPI
xCryptLibFreeRC4Key(PXRC4_KEY key);

/// <summary> Initialize an allocated RC4 key with the specified key bytes.</summary>
/// <param name="pxRc4Key"> The allocated RC4 key to initialize. </param>
/// <param name="pbKey"> The bytes of the key. </param>
/// <param name="cbKey"> The number of bytes in the key. It can be in the range [1, 256].</param>
/// <param name="pParamList"> List of parameters.  Must be <c>NULL</c> or empty. </param>
/// <returns> CRYPTO_SUCCESS if the key was successfully initialized </returns>
/// \ingroup RC4
CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibInitRC4Key(
    PXRC4_KEY             pxRc4Key,
    unsigned char*        pbKey,
    size_t                cbKey,
    PxCryptLibParamList   pParamList);

/// <summary> Encrypt / Decrypt in place with RC4</summary>
/// <param name="pxRc4Key"> The key to encrypt with.  Must be allocated and initialized. </param>
/// <param name="pbData"> The buffer to be encrypted.  Must be one or more bytes. The result is stored in the same buffer. </param>
/// <param name="cbData"> The length of <paramref name="pbData"/> in bytes. </param>
/// <param name="pParamList"> List of parameters.  Must be <c>NULL</c> or empty. </param>
/// <returns> CRYPTO_SUCCESS if the operation was successful. </returns>
/// <seealso cref="xCryptLibInitRC4Key"/>
/// <seealso cref="xCryptLibAllocateRC4Key"/>
/// \ingroup RC4
CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibRC4(
    PXRC4_KEY         pxRc4Key,
    unsigned char*          pbData,
    size_t                  cbData,
    PxCryptLibParamList     pParamList);


/*
 * AES Functionality
 */
#ifndef AES_BLOCK_SIZE
    /// The size of an AES block. \ingroup AES
    #define AES_BLOCK_SIZE (16)
#endif

struct _XAES_KEY;
/// Pointer to an AES context object (opaque). \ingroup AES
typedef struct _XAES_KEY* PXAES_KEY;

/// <summary> Allocate an AES key. </summary>
/// <param name="pParamList"> List of parameters.  Must be <c>NULL</c> or empty. </param>
/// <returns> An allocated key, or <c>NULL</c>. </returns>
/// <see cref="xCryptLibFreeAESKey"/>
/// \ingroup AES
PXAES_KEY
XCRYPTLIBAPI
xCryptLibAllocateAESKey(PxCryptLibParamList pParamList);

/// <summary> Free an allocated AES key. </summary>
/// <param name="key"> The key to be freed.  Must be non-<c>NULL</c></param>
/// <remarks>
///   Zeroes the key material from memory.
/// </remarks>
/// \ingroup AES
void
XCRYPTLIBAPI
xCryptLibFreeAESKey(PXAES_KEY key);

/// <summary> Generate a random IV for use with AES. </summary>
/// <param name="rgbIV"> A buffer to store the IV. Must be AES_BLOCK_SIZE bytes </param>
/// <returns> <c>CRYPTO_SUCCESS</c> if an IV was successfully generated. 
/// <remarks>
/// Calls <see cref="xCryptRandom"/> internally.  
/// </remarks>
/// \ingroup AES
CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibAESRandomIV(unsigned char rgbIV[AES_BLOCK_SIZE]);

/// <summary> Initialize an allocated AES key with the specified key bytes.</summary>
/// <param name="pxAesKey"> The allocated AES key to initialize. </param>
/// <param name="pbKey"> The bytes of the key. </param>
/// <param name="cbKey"> The number of bytes in the key.  Must be one of 16, 24, or 32.</param>
/// <param name="pParamList"> List of parameters.  Must be <c>NULL</c> or empty. </param>
/// <returns> CRYPTO_SUCCESS if the key was successfully initialized </returns>
/// <remarks>
///    This expands the provided AES key into round keys. 
///    An allocated AES key may be initialized multiple times with different <paramref name="pbKey/> values,
///    however, if the application is frequently switching between multiple keys it may be more computationally
///    efficient to have multiple key objects (but memory usage will be increased). 
///
///  The parameter <paramref name="cbKey"/> selects whether AES 128, 192 or 256 is used.
/// </remarks>
/// \ingroup AES
CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibInitAESKey(
    PXAES_KEY             pxAesKey, 
    const unsigned char*  pbKey, 
    const size_t          cbKey,     
    PxCryptLibParamList   pParamList);

/// <summary> Encrypt with AES in CBC mode, with PKCS#7 padding</summary>
/// <param name="pxAesKey"> The key to encrypt with.  Must be allocated and initialized. </param>
/// <param name="pbIV"> The IV to use for encryption. </param>
/// <param name="cbIV"> The length of the IV in bytes. Must be AES_BLOCKSIZE. </param>
/// <param name="pbData"> The data to be encrypted.  Must be one or more bytes. </param>
/// <param name="cbData"> The length of <paramref name="pbData"/> in bytes. </param>
/// <param name="cbDataMaxSize"> The number of bytes allocated in <paramref name="pbData"/>. Must always
///    greater than the data <paramref name="cbData"/> to account for padding overhead.</param>
/// <param name="pcbDataOutput"> The new size of the data, after being encrypted. If <paramref name="pbData"/> is 
///    <c>NULL</c>, then this is the number of bytes that would be required for <paramref name="cbData"/> bytes
///    of plaintext. </param>
/// <param name="pParamList"> List of parameters.  Must be <c>NULL</c> or empty. </param>
/// <returns> CRYPTO_SUCCESS if the encryption was successful. </returns>
/// <remarks>
/// The padding scheme is described here: http://tools.ietf.org/html/rfc5652#section-6.3 
///  and here: http://tools.ietf.org/html/rfc2315 (Section 10.3). 
/// </remarks>
/// <seealso cref="xCryptLibInitAESKey"/>
/// <seealso cref="xCryptLibAllocateAESKey"/>
/// <seealso cref="xCryptLibAESCBCDecryptAndUnpad"/>
/// \ingroup AES
CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibAESCBCEncryptAndPad(
    const PXAES_KEY         pxAesKey, 
    const unsigned char*    pbIV,    
    size_t                  cbIV, 
    unsigned char*          pbData,  
    size_t                  cbData,        
    size_t                  cbDataMaxSize, 
    size_t*                 pcbDataOutput, 
    PxCryptLibParamList     pParamList); 

/// <summary> Decrypts the ciphertext, checks and removes the padding applied by encrypt. </summary>
/// <param name="pxAesKey"> The key to decrypt with.  Must be allocated and initialized. </param>
/// <param name="pbIV"> The IV to use for decryption. </param>
/// <param name="cbIV"> The length of the IV in bytes. Must be AES_BLOCKSIZE. </param>
/// <param name="pbData"> The ciphertext to be decrypted.  Must be one or more bytes. </param>
/// <param name="cbData"> The length of <paramref name="pbData"/> in bytes. </param>
/// <param name="pcbDataOutput"> The length of plaintext data left in <paramref name="pbData"/> after decryption. 
///     This willl <b> always</b> be less than <paramref name="cbData"/>.  Will be set to zero if decryption fails. </param>
/// <param name="pParamList"> List of parameters.  Must be <c>NULL</c> or empty.</param>
/// <returns> CRYPTO_SUCCESS if the decryption is successful, and CRYPTO_ERROR_DECRYPTION_FAILURE
///     if the padding is invalid.</returns>
/// <remarks>
///    Note that no integrity checking is performed, and if decryption succeeds, this is not a guarantee
///    that the plaintext data is the same as was encrypted.  A message authentication code (MAC) should
///    be applied to the ciphertext, and decryption should be conditional on successful verification of
///    the MAC. xCryptLib includes HMAC.   
/// </remarks>
/// <seealso cref="xCryptLibAESCBCEncryptAndPad"/>
/// \ingroup AES
CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibAESCBCDecryptAndUnpad(
    const PXAES_KEY         pxAesKey, 
    const unsigned char*    pbIV,    
    size_t                  cbIV, 
    unsigned char*          pbData,  
    size_t                  cbData,         
    size_t*                 pcbDataOutput, 
    PxCryptLibParamList     pParamList); 

/// <summary> Encrypt data with AES in CBC mode, with no padding. Suitable for streaming data.</summary>
/// <param name="pxAesKey"> The key to encrypt with.  Must be allocated and initialized. </param>
/// <param name="pbIV"> The IV to use for encryption. </param>
/// <param name="cbIV"> The length of the IV in bytes. Must be AES_BLOCKSIZE. </param>
/// <param name="pbIVOut"> The IV to use to encrypt the next part in the stream. May be NULL if the chaining IV is not required. </param>
/// <param name="cbIVOut"> The length of the <paramref name="pbIVOut"/> buffer, in bytes. Must be AES_BLOCKSIZE 
///     if <paramref name="pbIVOut"/> non-<c>NULL</c>. </param>
/// <param name="pbData"> The plaintext to be encrypted.   </param>
/// <param name="cbData"> The length of <paramref name="pbData"/> in bytes. Must a nonzero multiple of AES_BLOCKSIZE. </param>
/// <param name="pParamList"> List of parameters.  Must be <c>NULL</c> or empty.</param>
/// <returns> Returns CRYPTO_SUCCESS if encryption was successful. </returns>
/// <remarks>
///     Can be used when encrypting a stream having <c>n</c> parts, the first <c>n-1</c> are encrypted 
///     with <see cref="xCryptLibAESCBCEncrypt"/>
///     and the last part is encrypted with <see cref="xCryptLibAESCBCEncryptAndPad"/>.
///     For the first <c>n-1</c> parts, <paramref name="cbData"/> <b> must </b> be a nonzero multiple of AES_BLOCK_SIZE.
///     The output length is the same size as the input length. 
///     The output IV from part <c>i</c> becomes the input IV for part <c>i+1</c>. 
///     The two IV parameters may overlap. 
/// </remarks>
/// <seealso cref="xCryptLibAESCBCEncryptAndPad"/>
/// \ingroup AES
CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibAESCBCEncrypt(
    const PXAES_KEY         pxAesKey, 
    const unsigned char*    pbIV,    
    size_t                  cbIV, 
    unsigned char*          pbIVOut, 
    size_t                  cbIVOut,     
    unsigned char*          pbData,  
    size_t                  cbData,  
    PxCryptLibParamList     pParamList);    

/// <summary> Decrypt with AES in CBC mode, with no padding. Suitable for streaming data.</summary>
/// <param name="pxAesKey"> The key to decrypt with.  Must be allocated and initialized. </param>
/// <param name="pbIV"> The IV to use for decryption. </param>
/// <param name="cbIV"> The length of the IV in bytes. Must be AES_BLOCKSIZE. </param>
/// <param name="pbIVOut"> The IV to use to decrypt the next part in the stream.  Maybe be <c>NULL</c> 
///      if the output IV is not required. </param>
/// <param name="cbIVOut"> The length of the <paramref name="pbIVOut"/> buffer, in bytes. Must be AES_BLOCKSIZE 
///      if <paramref name="pbIVOut"/> is non-<c>NULL</c>. </param>
/// <param name="pbData"> The plaintext to be decrypted.   </param>
/// <param name="cbData"> The length of <paramref name="pbData"/> in bytes. Must a nonzero multiple of AES_BLOCKSIZE. </param>
/// <param name="pParamList"> List of parameters.  Must be <c>NULL</c> or empty.</param>
/// <returns> CRYPTO_SUCCESS if decryption was successful. </returns>
/// <remarks>
///     Can be used when decrypting a stream having <c>n</c> parts, the first <c>n-1</c> are decrypted
///     with <see cref="xCryptLibAESCBCDecrypt"/>
///     and the last part is decrypted with <see cref="xCryptLibAESCBCDecryptAndUnpad"/>.
///     For the first <c>n-1</c> parts, <paramref name="cbData"/> <b> must </b> be a nonzero multiple of AES_BLOCK_SIZE and the
///     the output length is the same size as the input length. 
///     The output IV from part <c>i</c> becomes the input IV for part <c>i+1</c>. 
///     The two IV parameters may overlap. 
/// </remarks>
/// <seealso cref="xCryptLibAESCBCDecryptAndUnpad"/>
///\ingroup AES
CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibAESCBCDecrypt(    
    const PXAES_KEY     pxAesKey, 
    unsigned char*      pbIV,    
    size_t              cbIV, 
    unsigned char*      pbIVOut, 
    size_t              cbIVOut,     
    unsigned char*      pbData,  
    size_t              cbData, 
    PxCryptLibParamList pParamList);     

/// <summary> Encrypt with AES in ECB mode, with PKCS#7 padding</summary>
/// <param name="pxAesKey"> The key to encrypt with.  Must be allocated and initialized. </param>
/// <param name="pbData"> The data to be encrypted.  Must be one or more bytes. </param>
/// <param name="cbData"> The length of <paramref name="pbData"/> in bytes. </param>
/// <param name="cbDataMaxSize"> The number of bytes allocated in <paramref name="pbData"/>. Must always
///    greater than the data <paramref name="cbData"/> to account for padding overhead.</param>
/// <param name="pcbDataOutput"> The new size of the data, after being encrypted. If <paramref name="pbData"/> is 
///    <c>NULL</c>, then this is the number of bytes that would be required for <paramref name="cbData"/> bytes
///    of plaintext. </param>
/// <param name="pParamList"> List of parameters.  Must be <c>NULL</c> or empty. </param>
/// <returns> CRYPTO_SUCCESS if the encryption was successful. </returns>
/// <remarks>
/// - The padding scheme is described here: http://tools.ietf.org/html/rfc5652#section-6.3 
///  and here: http://tools.ietf.org/html/rfc2315 (Section 10.3). 
/// - This block cipher mode is only provided 
/// for backwards compatibility and is considered 
/// insecure. Any use of it must be justified and 
/// reviewed by the crypto board.
/// </remarks>
/// <seealso cref="xCryptLibInitAESKey"/>
/// <seealso cref="xCryptLibAllocateAESKey"/>
/// <seealso cref="xCryptLibAESECBDecryptAndUnpad"/>
/// \ingroup AES
CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibAESECBEncryptAndPad(
    const PXAES_KEY         pxAesKey,
    unsigned char*          pbData,
    size_t                  cbData,
    size_t                  cbDataMaxSize,
    size_t*                 pcbDataOutput,
    PxCryptLibParamList     pParamList);

/// <summary> Decrypts the ciphertext with AES in ECB mode, checks and removes the padding applied by encrypt. </summary>
/// <param name="pxAesKey"> The key to decrypt with.  Must be allocated and initialized. </param>
/// <param name="pbData"> The ciphertext to be decrypted.  Must be one or more bytes. </param>
/// <param name="cbData"> The length of <paramref name="pbData"/> in bytes. </param>
/// <param name="pcbDataOutput"> The length of plaintext data left in <paramref name="pbData"/> after decryption. 
///     This will <b> always</b> be less than <paramref name="cbData"/>.  Will be set to zero if decryption fails. </param>
/// <param name="pParamList"> List of parameters.  Must be <c>NULL</c> or empty.</param>
/// <returns> CRYPTO_SUCCESS if the decryption is successful, and CRYPTO_ERROR_DECRYPTION_FAILURE
///     if the padding is invalid.</returns>
/// <remarks>
///    - Note that no integrity checking is performed, and if decryption succeeds, this is not a guarantee
///    that the plaintext data is the same as was encrypted.  A message authentication code (MAC) should
///    be applied to the ciphertext, and decryption should be conditional on successful verification of
///    the MAC. xCryptLib includes HMAC.   
///     - This block cipher mode is only provided 
///     for backwards compatibility and is considered 
///     insecure. Any use of it must be justified and 
///     reviewed by the crypto board.
/// </remarks>
/// <seealso cref="xCryptLibAESECBEncryptAndPad"/>
/// \ingroup AES
CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibAESECBDecryptAndUnpad(
    const PXAES_KEY         pxAesKey,
    unsigned char*          pbData,
    size_t                  cbData,
    size_t*                 pcbDataOutput,
    PxCryptLibParamList     pParamList);

/// <summary> Encrypt data with AES in ECB mode, with no padding. Suitable for streaming data.</summary>
/// <param name="pxAesKey"> The key to encrypt with.  Must be allocated and initialized. </param>
/// <param name="pbData"> The plaintext to be encrypted.   </param>
/// <param name="cbData"> The length of <paramref name="pbData"/> in bytes. Must a nonzero multiple of AES_BLOCKSIZE. </param>
/// <param name="pParamList"> List of parameters.  Must be <c>NULL</c> or empty.</param>
/// <returns> Returns CRYPTO_SUCCESS if encryption was successful. </returns>
/// <remarks>
///     - Can be used when encrypting a stream having <c>n</c> parts, the first <c>n-1</c> are encrypted 
///     with <see cref="xCryptLibAESECBEncrypt"/>
///     and the last part is encrypted with <see cref="xCryptLibAESECBEncryptAndPad"/>.
///     For the first <c>n-1</c> parts, <paramref name="cbData"/> <b> must </b> be a nonzero multiple of AES_BLOCK_SIZE.
///     The output length is the same size as the input length. 
///     - This block cipher mode is only provided 
///     for backwards compatibility and is considered 
///     insecure. Any use of it must be justified and 
///     reviewed by the crypto board.
/// </remarks>
/// <seealso cref="xCryptLibAESECBEncryptAndPad"/>
/// \ingroup AES
CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibAESECBEncrypt(
    const PXAES_KEY         pxAesKey,
    unsigned char*          pbData,
    size_t                  cbData,
    PxCryptLibParamList     pParamList);

/// <summary> Decrypt with AES in ECB mode, with no padding. Suitable for streaming data.</summary>
/// <param name="pxAesKey"> The key to decrypt with.  Must be allocated and initialized. </param>
/// <param name="pbData"> The plaintext to be decrypted.   </param>
/// <param name="cbData"> The length of <paramref name="pbData"/> in bytes. Must a nonzero multiple of AES_BLOCKSIZE. </param>
/// <param name="pParamList"> List of parameters.  Must be <c>NULL</c> or empty.</param>
/// <returns> CRYPTO_SUCCESS if decryption was successful. </returns>
/// <remarks>
///     - Can be used when decrypting a stream having <c>n</c> parts, the first <c>n-1</c> are decrypted
///     with <see cref="xCryptLibAESECBDecrypt"/>
///     and the last part is decrypted with <see cref="xCryptLibAESECBDecryptAndUnpad"/>.
///     For the first <c>n-1</c> parts, <paramref name="cbData"/> <b> must </b> be a nonzero multiple of AES_BLOCK_SIZE and the
///     the output length is the same size as the input length. 
///     - This block cipher mode is only provided 
///     for backwards compatibility and is considered 
///     insecure. Any use of it must be justified and 
///     reviewed by the crypto board.
/// </remarks>
/// <seealso cref="xCryptLibAESECBDecryptAndUnpad"/>
///\ingroup AES
CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibAESECBDecrypt(
    const PXAES_KEY     pxAesKey,
    unsigned char*      pbData,
    size_t              cbData,
    PxCryptLibParamList pParamList);

/// <summary> Encrypt with AES in GCM mode</summary>
/// <param name="pxAesKey"> The key to encrypt with.  Must be allocated and initialized. </param>
/// <param name="pbIV"> Initialization vector for GCM.  Must be exactly 12 bytes. </param>
/// <param name="cbIV"> The length of <paramref name="pbIV"/> in bytes. </param>
/// <param name="pbInput"> The data to be encrypted.  Must be one or more bytes. </param>
/// <param name="cbInput"> The length of <paramref name="pbInput"/> in bytes. </param>
/// <param name="pbOutput"> The output buffer. Must be <paramref name="cbInput"/> bytes. </param>
/// <param name="pbAuthData"> Authentication data for GCM.  Must be exactly 12 bytes. </param>
/// <param name="cbAuthData"> The length of <paramref name="pbAuthData"/> in bytes. </param>
/// <param name="pbTag"> Authentication tag for GCM.  Must be between 12 and 16 bytes (incl.). </param>
/// <param name="cbTag"> The length of <paramref name="pbTag"/> in bytes. </param>
/// <param name="pParamList"> List of parameters.  Must be <c>NULL</c> or empty. </param>
/// <returns> CRYPTO_SUCCESS if the encryption was successful. </returns>
/// <returns> CRYPTO_ERROR_ENCRYPTION_FAILED if the encryption failed. </returns>
/// <returns> CRYPTO_ERROR_INVALID_PARAMETER if one of the parameters is invalid. </returns>
/// <seealso cref="xCryptLibInitAESKey"/>
/// <seealso cref="xCryptLibAllocateAESKey"/>
/// \ingroup AES
CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLib_AESGCM_Encrypt(
    const PXAES_KEY     pxAesKey,
    unsigned char*      pbIV,
    size_t              cbIV,
    unsigned char*      pbInput,
    size_t              cbInput,
    unsigned char*      pbOutput,
    unsigned char*      pbAuthData,
    size_t              cbAuthData,
    unsigned char*      pbTag,
    size_t              cbTag,
    PxCryptLibParamList pParamList);

/// <summary> Decrypt with AES in GCM mode</summary>
/// <param name="pxAesKey"> The key to decrypt with.  Must be allocated and initialized. </param>
/// <param name="pbIV"> Initialization vector for GCM.  Must be exactly 12 bytes. </param>
/// <param name="cbIV"> The length of <paramref name="pbIV"/> in bytes. </param>
/// <param name="pbInput"> The data to be decrypted.  Must be one or more bytes. </param>
/// <param name="cbInput"> The length of <paramref name="pbInput"/> in bytes. </param>
/// <param name="pbOutput"> The output buffer. Must be <paramref name="cbInput"/> bytes. </param>
/// <param name="pbAuthData"> Authentication data for GCM.  Must be exactly 12 bytes. </param>
/// <param name="cbAuthData"> The length of <paramref name="pbAuthData"/> in bytes. </param>
/// <param name="pbTag"> Authentication tag for GCM.  Must be between 12 and 16 bytes (incl.). </param>
/// <param name="cbTag"> The length of <paramref name="pbTag"/> in bytes. </param>
/// <param name="pParamList"> List of parameters.  Must be <c>NULL</c> or empty. </param>
/// <returns> CRYPTO_SUCCESS if the decryption was successful. </returns>
/// <returns> CRYPTO_ERROR_DECRYPTION_FAILED if the decryption / authentication failed. </returns>
/// <returns> CRYPTO_ERROR_INVALID_PARAMETER if one of the parameters is invalid. </returns>
/// <seealso cref="xCryptLibInitAESKey"/>
/// <seealso cref="xCryptLibAllocateAESKey"/>
/// \ingroup AES
CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLib_AESGCM_Decrypt(
    const PXAES_KEY     pxAesKey,
    unsigned char*      pbIV,
    size_t              cbIV,
    unsigned char*      pbInput,
    size_t              cbInput,
    unsigned char*      pbOutput,
    unsigned char*      pbAuthData,
    size_t              cbAuthData,
    unsigned char*      pbTag,
    size_t              cbTag,
    PxCryptLibParamList pParamList);

/*
 *
 *  Elliptic Curve Functionality
 *
 */

/// String to identify the named curve NIST P-256.      \ingroup ECC
#define XCRYPTLIB_NIST_P256 L"NIST P256 Curve"
/// String to identify the named curve NIST P-384.      \ingroup ECC
#define XCRYPTLIB_NIST_P384 L"NIST P384 Curve"
/// String to identify the named curve NIST P-521.      \ingroup ECC
#define XCRYPTLIB_NIST_P521 L"NIST P521 Curve"



struct _ELLIPTIC_CURVE;
/// Pointer to an elliptic curve object (opaque).       \ingroup ECC
typedef struct _ELLIPTIC_CURVE* PELLIPTIC_CURVE;

struct _ELLIPTIC_CURVE_PUBLIC_KEY;
/// Pointer to an elliptic curve public key object (opaque).       \ingroup ECC
typedef struct _ELLIPTIC_CURVE_PUBLIC_KEY* PELLIPTIC_CURVE_PUBLIC_KEY;

struct _ELLIPTIC_CURVE_PRIVATE_KEY;
/// Pointer to an elliptic curve private key object (opaque).       \ingroup ECC
typedef struct _ELLIPTIC_CURVE_PRIVATE_KEY* PELLIPTIC_CURVE_PRIVATE_KEY;


struct _SECRET;
/// Pointer to a shared secret object for use with key agreement primitives (e.g., output of ECDH).
/// Not to be cofused with a private key object (such as <see cref="PELLIPTIC_CURVE_PRIVATE_KEY/>).     \ingroup ECC
typedef struct _SECRET* PSECRET;

// TODO: should this be part of the public API for now? 
// Seems that it doesn't support anything other than curves from name. 
// Either way we need to document how to use this, or that it shouldn't be used
CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibInitializeEllipticCurve(
    PxCryptLibParamList pParamList,
    PELLIPTIC_CURVE     *ppEllipticCurve);

/// <summary> Initialize an object representing a named elliptic curve. </summary>
/// <param name="pwszCurveName"> The name of the elliptic curve. </param>
/// <param name="pParamList"> The list of parameters, must be <c>NULL</c> or empty. </param>
/// <param name="ppEllipticCurve"> A pointer to the elliptic curve object that will be initialized.</param>
/// <returns> <c>CRYPTO_SUCCESS</c> or an error. </returns>
/// <remarks> 
///      The name must be one of the constants defined in xCryptLib. 
///      This function allocates memory required for the curve.  Use <see cref="xCryptLibFreeEllipticCurve"/> to free it. 
/// </remarks>
/// <seealso cref="XCRYPTLIB_NIST_P256"/>
/// <seealso cref="XCRYPTLIB_NIST_P384"/>
/// <seealso cref="XCRYPTLIB_NIST_P521"/>
/// <seealso cref="xCryptLibFreeEllipticCurve"/>
/// \ingroup ECC
CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibInitializeEllipticCurveFromName(
    const wchar_t       *pwszCurveName,
    PxCryptLibParamList pParamList,
    PELLIPTIC_CURVE     *ppEllipticCurve);

/// <summary> Frees an object representing an elliptic curve. </summary>
/// <param name="pEllipticCurve"> A pointer to the elliptic curve object that will be freed.</param>
/// <remarks>
///     Callers must ensure <paramref name="pEllipticCurve"/> is non-<c>NULL</c>.
/// </remarks>
/// <seealso cref="xCryptLibInitializeEllipticCurveFromName"/>
/// <seealso cref="xCryptLibInitializeEllipticCurve"/>
/// \ingroup ECC
void
XCRYPTLIBAPI
xCryptLibFreeEllipticCurve(
    PELLIPTIC_CURVE  pEllipticCurve);

/// <summary> Get the size of an EC public key object (key + metadata) for a given curve. </summary>
/// <param name="pEllipticCurve"> A pointer to the elliptic curve object associated with the public key.</param>
/// <returns> An integer representing the number of bytes required by xCryptLib to represent the public key. </returns>
/// <remarks>
///     All public keys associated to a given curve have the same size.  
/// </remarks>
/// <seealso cref="xCryptLibEllipticCurvePrivateKeyObjectSize"/>
/// \ingroup ECC
size_t
XCRYPTLIBAPI
xCryptLibEllipticCurvePublicKeyObjectSize(
    const PELLIPTIC_CURVE pEllipticCurve);

/// <summary> Get the size of an EC private key object (key + metadata) for a given curve. </summary>
/// <param name="pEllipticCurve"> A pointer to the elliptic curve object associated with the private key.</param>
/// <returns> An integer representing the number of bytes required by xCryptLib to represent the private key. </returns>
/// <remarks>
///     All private keys associated to a given curve have the same size.  
/// </remarks>
/// <seealso cref="xCryptLibEllipticCurvePublicKeyObjectSize"/>
/// \ingroup ECC
size_t
XCRYPTLIBAPI
xCryptLibEllipticCurvePrivateKeyObjectSize(
    const PELLIPTIC_CURVE pEllipticCurve);

/// <summary> Allocate memory for a public key. </summary>
/// <param name="pEllipticCurve"> A pointer to the elliptic curve object associated with the public key.</param>
///   <param name="pParamList"> must be <c>NULL</c> or empty</param>
/// <returns> A pointer to an allocated public key object, or <c>NULL</c> if an error has occured. </returns>
/// <seealso cref="xCryptLibEllipticCurveFreePublicKey"/>
/// \ingroup ECC
PELLIPTIC_CURVE_PUBLIC_KEY
XCRYPTLIBAPI
xCryptLibEllipticCurveAllocatePublicKey(
    PELLIPTIC_CURVE     pEllipticCurve,
    PxCryptLibParamList pParamList);

/// <summary> Free a public key. </summary>
/// <param name="pEllipticCurvePoint"> The public key object to free.</param>
/// <remarks> 
///     Callers must ensure <paramref name="pEllipticCurvePoint"/> is non-<c>NULL</c>.
/// </remarks>
/// \ingroup ECC
void
XCRYPTLIBAPI
xCryptLibEllipticCurveFreePublicKey(
    PELLIPTIC_CURVE_PUBLIC_KEY  pEllipticCurvePoint);

/// <summary> Initialize an allocated public key. </summary>
///   <param name="pbX"> X-coordinate bytes in little endian</param>
///   <param name="cbX"> size of pbX (in bytes)</param>
///   <param name="pbY"> Y-coordinate bytes in little endian</param>
///   <param name="cbY"> size of pbY (in bytes)</param>
///   <param name="pPublicKey"> allocated public key</param>
///   <param name="pParamList"> must be <c>NULL</c> or empty</param>
///   <returns> <c>CRYPTO_SUCCESS</c> if initialization is successful. </returns>
/// <remarks>
///     The size of the input buffers must be at least <c>n</c> bytes, 
///     where <c>n</c> is the size returned by <see cref="xCryptLibEllipticCurveGetFieldElementLength"/>.
///     If the input data is fewer bytes, you must zero-pad it to <c>n</c> byte buffers. 
///     For larger inputs, the additional bytes are ignored.
/// </remarks>
/// \ingroup ECC
CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibEllipticCurveInitializePublicKey(
    const unsigned char         *pbX,
    size_t                      cbX,
    const unsigned char         *pbY,
    size_t                      cbY,
    PELLIPTIC_CURVE_PUBLIC_KEY  pPublicKey, 
    PxCryptLibParamList         pParamList);

/// <summary> Allocated a private key object. </summary>
///   <param name="pEllipticCurve"> The elliptic curve used to create the ECDSA signature</param>
///   <param name="pParamList"> must be <c>NULL</c> or empty</param>
///   <returns> A pointer to the private key object if allocation was successful, or <c>NULL</c> if not. </returns>
/// <remarks>
///     Free with <see cref="xCryptLibEllipticCurveFreePrivateKey"/>.
/// </remarks>
///  <seealso cref="xCryptLibEllipticCurveFreePrivateKey"/>
/// \ingroup ECC
PELLIPTIC_CURVE_PRIVATE_KEY
XCRYPTLIBAPI
xCryptLibEllipticCurveAllocatePrivateKey(
    PELLIPTIC_CURVE     pEllipticCurve,
    PxCryptLibParamList pParamList);

/// <summary> Free a private key object. </summary>
///   <param name="pEllipticCurvePrivateKey"> The private key to be freed </param>
/// <remarks>
///     The caller must ensure that the input is non-null.
/// </remarks>
///  <seealso cref="xCryptLibEllipticCurveAllocatePrivateKey"/>
/// \ingroup ECC
void
XCRYPTLIBAPI
xCryptLibEllipticCurveFreePrivateKey(
    PELLIPTIC_CURVE_PRIVATE_KEY pEllipticCurvePrivateKey);

/// <summary> Initialize an allocated private key. </summary>
///   <param name="pb"> private key bytes in little endian</param>
///   <param name="cb"> size of pb (in bytes)</param>
///   <param name="pPrivateKey"> allocated private key</param>
///   <param name="pParamList"> must be <c>NULL</c> or empty</param>
///   <returns> <c>CRYPTO_SUCCESS</c> if initialization is successful. </returns>
/// <remarks>
///     The size of the input buffer must be <c>n</c> bytes, 
///     where <c>n</c> is the size <c>cbSignatureS</c> returned by <see cref="xCryptLibEllipticCurvePrivateKeyLength"/>.
/// </remarks>
/// \ingroup ECC
CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibEllipticCurveInitializePrivateKey(
    const unsigned char         *pb,
    size_t                      cb,
    PELLIPTIC_CURVE_PRIVATE_KEY pPrivateKey,
    PxCryptLibParamList         pParamList);

/// <summary> Generate an ECC key pair. </summary>
///   <param name="pPublicKey"> Allocated public key object</param>
///   <param name="pPrivateKey">Allocated private key object</param>
///   <param name="pParamList"> must be <c>NULL</c> or empty</param>
///   <returns> <c>CRYPTO_SUCCESS</c> if key generation is successful. </returns>
/// <remarks>
///  The parameters <paramref name="pPublicKey"/> and <paramref name="pPriveateKey"/> must be allocated, <see cref="xCryptLibEllipticCurveAllocatePublicKey"/>
///  and <see cref="xCryptLibEllipticCurveAllocatePrivateKey"/>.
/// </remarks>
/// \ingroup ECC
CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibEllipticCurveGenerateKeyPair(
    PELLIPTIC_CURVE_PUBLIC_KEY  pPublicKey, 
    PELLIPTIC_CURVE_PRIVATE_KEY pPrivateKey,
    PxCryptLibParamList         pParamList);

/// <summary> Check whether a public and private key pair are consistent. </summary>
///   <param name="pPublicKey"> Allocated and initialized public key object</param>
///   <param name="pPrivateKey">Allocated and initialized private key object</param>
///   <param name="pParamList"> must be <c>NULL</c> or empty</param>
///   <returns> <c>CRYPTO_SUCCESS</c> if the keypair is valid. </returns>
/// <remarks>
///  Recomputes the public key point from the private key and curve params, then compares
///  to the value provided in <paramref name="pPublicKey"/>.
/// </remarks>
/// \ingroup ECC
CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibEllipticCurveValidateKeyPair(
    const PELLIPTIC_CURVE_PUBLIC_KEY    pPublicKey, 
    const PELLIPTIC_CURVE_PRIVATE_KEY   pPrivateKey,
    PxCryptLibParamList                 pParamList);

/// <summary> Get the size (in bytes) of the two ECDSA signature components output by <see cref="xCryptLibEllipticCurveDSASign"/> </summary>
///   <param name="pEllipticCurve"> The elliptic curve used to create the ECDSA signature</param>
///   <param name="pcbSignatureR"> Output parameter: the size of the first component of the signature output by <see cref="xCryptLibEllipticCurveDSASign"/> </param>
///   <param name="pcbSignatureS"> Output paramter: the size of the second component of the signature output by <see cref="xCryptLibEllipticCurveDSASign"/> </param>
/// <c>SignatureR</c> and <c>SignatureS</c>, output by <c>xCryptLibEllipticCurveDSASign</c>
///   <returns> <c>CRYPTO_SUCCESS</c> unless there is an error, and the output parameters <paramref name="pcbSignatureR"/> and <paramref name="pCbSignatureR"/>. </returns>
/// <remarks> 
///    Note that this should be used by callers to determine the size of input buffers required by <see cref="xCryptLibEllipticCurveDSASign"/>.  
///    When the field size is not a multiple of the word size (as is the case with NIST P-521 on 32 and 64-bit architectures), xCryptLib will allocate new buffers, 
///    with size rounded up to the nearest multiple of the word size.  Callers may avoid this allocation by ensuring their input buffers lengths are a multiple of the word size. 
///    The extra bytes will not be a part of the signature -- it's two components will have <paramref name="pcbSignatureR"/> and <paramref name="pCbSignatureS"/> bytes, respectively.
///    <p>
///    <example>
///         <b>Example.</b> For NIST P-521, <see cref="xCryptLibEllipticCurveDSASignatureLength"/> will return (66, 66).  On a 32-bit platform, since 
///         <see cref="xCryptLibEllipticCurveDSASign"/> internally operates on 32-bit words, it will allocate new buffers with 68 bytes (the next multiple of 4 bytes).
///         On 64-bit platforms, it will allocate new buffers with 72 bytes (the next multiple of 8 bytes). If callers instead provide 68 or 72 bytes, no allocation
///         is performed, and callers should only treat the first 66 bytes of output (it's little endian) as part of the signature. 
///    </p>
///       </example>
/// </remarks>
/// \ingroup ECC
CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibEllipticCurveDSASignatureLength(
    const PELLIPTIC_CURVE   pEllipticCurve,
    size_t                  *pcbSignatureR,
    size_t                  *pcbSignatureS);

/// <summary>
/// Generates an ECDSA signature
/// </summary>
/// <param name="pEllipticCurve"> The curve associated with the signer's keypair.</param>
/// <param name="pPrivateKey"> The signing key. </param>
/// <param name="pbHash">The hash digest to sign</param>
/// <param name="cbHash">Length of <paramref name="pbHash"/> in bytes.</param>
/// <param name="pbSignatureR"><b>(output)</b>The first signature component.</param>
/// <param name="cbSignatureR">Length of provided buffer <paramref name="pbSignatureR"/> in bytes.</param>
/// <param name="pbSignatureS"><b>(output)</b>The second signature component.</param>
/// <param name="cbSignatureS">Length of provided buffer <paramref name="pbSignatures"/> in bytes.</param>
/// <param name="pParamList">Parameter list.  Must be <c>NULL</c> or empty.</param>
/// <returns>An ECDSA signature (<c>R</c>, <c>S</c>) in the output
/// buffers <paramref name="pbSignatureR"/> and <paramref name="pbSignatureS"/>.  The number of
/// output bytes written to these buffers is given by <see cref="xCryptLibEllipticCurveDSASignatureLength"/>.
/// If signature generation was successful, <c>CRYPTO_SUCCESS</c> is returned.
///  </returns>
/// <remarks>
///  The required size of the output buffers <paramref name="pbSignatureR"/> and <paramref name="pbSignatureS"/> 
///  is given by <see cref="xCryptLibEllipticCurveDSASignatureLength"/>
/// </remarks>
/// <seealso cref="xCryptLibEllipticCurveDSAVerify"/>
/// <seealso cref="xCryptLibEllipticCurveDSASignatureLength"/>
/// \ingroup ECC
CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibEllipticCurveDSASign(
    const PELLIPTIC_CURVE               pEllipticCurve,
    const PELLIPTIC_CURVE_PRIVATE_KEY   pPrivateKey,
    const unsigned char*                pbHash,
    size_t                              cbHash,
    unsigned char*                      pbSignatureR,
    size_t                              cbSignatureR,
    unsigned char*                      pbSignatureS,
    size_t                              cbSignatureS,
    PxCryptLibParamList                 pParamList);

/// <summary> 
///     Verify an ECDSA signature. 
/// </summary>
/// <param name="pEllipticCurve"> The curve associated with the signer's keypair.</param>
/// <param name="pPublicKey"> The public key of the signer </param>
/// <param name="pbHash">The hash the signature puportedly authenticates. </param>
/// <param name="cbHash">Length of <paramref name="pbHash"/> in bytes.</param>
/// <param name="pbSignatureR"><b>(output)</b>The first signature component.</param>
/// <param name="cbSignatureR">Length of provided buffer <paramref name="pbSignatureR"/> in bytes.</param>
/// <param name="pbSignatureS"><b>(output)</b>The second signature component.</param>
/// <param name="cbSignatureS">Length of provided buffer <paramref name="pbSignatures"/> in bytes.</param>
/// <param name="pfValidSignature">Output parameter, set to <c>CRYPTO_TRUE</c> if the signature is valid, and
/// <c>CRYPTO_FALSE</c> if invalid. </param>
/// <param name="pParamList">Parameter list.  Must be <c>NULL</c> or empty.</param>
/// <remarks> Callers should also check the return value, which may indicate
/// the computation failed (<c>CRYPTO_ERROR_SIGANTURE_CHECK_FAILED</c>) or 
/// that the inputs are invalid (<c>CRYPTO_ERROR_INVALID_INPUT</c>).
///
/// If <paramref name="cbSignatureR"/> and <paramref name="cbSignatureS"/> are as large as the sizes output
/// by  <see cref="xCryptLibEllipticCurveDSASignatureLength"/> (zero padded, if the signature values are smaller), 
/// an allocation may be avoided (for many signatures and parameters).  
/// </remarks>
/// \ingroup ECC
CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibEllipticCurveDSAVerify(
    const PELLIPTIC_CURVE               pEllipticCurve,
    const PELLIPTIC_CURVE_PUBLIC_KEY    pPublicKey,          
    const unsigned char*                pbHash,
    size_t                              cbHash,
    const unsigned char*                pbSignatureR,
    size_t                              cbSignatureR,
    const unsigned char*                pbSignatureS,
    size_t                              cbSignatureS,
    CRYPTO_BOOL                         *pfValidSignature,
    PxCryptLibParamList                 pParamList);

/// <summary>
///     Get the number of bytes required to store a secret object size (object of type <see cref="PSECRET"/>)
///     associated with the given elliptic curve. 
/// <summary>
/// <param name="pEllipticCurve"> An elliptic curve </param>
/// <returns> The number of bytes required to store a secret object. </returns>
/// \ingroup ECC
size_t
XCRYPTLIBAPI
xCryptLibEllipticCurveGetSecretObjectSize(
    const PELLIPTIC_CURVE pEllipticCurve);

/// <summary> 
///       Get the size of a field element (in bytes) associated to an elliptic curve.
/// </summary>
/// <param name="pEllipticCurve"> An elliptic curve </param>
/// <returns> The size in bytes of a field element associated with <paramref name="pEllipticCurve"/> </returns>
/// <remarks>
///    Each elliptic curve is defined over a field, the x and y coordinates of a point on the curve are elements of this field. 
///    In some API calls, input buffers must be large enough to represent a field element. 
/// </remarks>
/// <seealso cref="pEllipticCurve"/>
/// \ingroup ECC
size_t
XCRYPTLIBAPI
xCryptLibEllipticCurveGetFieldElementLength(
    const PELLIPTIC_CURVE pEllipticCurve);

/// <summary> 
///       Get the size of a private key (in bytes) associated to an elliptic curve.
/// </summary>
/// <param name="pEllipticCurve"> An elliptic curve </param>
/// <returns> The size in bytes of a private key associated with <paramref name="pEllipticCurve"/> </returns>
/// <remarks>
///    All private keys associated with a given elliptic curve have the same size. 
/// </remarks>
/// <seealso cref="pEllipticCurve"/>
/// \ingroup ECC
size_t 
XCRYPTLIBAPI
xCryptLibEllipticCurvePrivateKeyLength(
    const PELLIPTIC_CURVE           pEllipticCurve);

CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibECExportPublicKey(
    const PELLIPTIC_CURVE_PUBLIC_KEY    pECPubKey,
    unsigned char*                      pbX,
    size_t                              cbX,
    unsigned char*                      pbY,
    size_t                              cbY,
    PxCryptLibParamList                 pParamList);

CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibECExportPrivateKey(
    const PELLIPTIC_CURVE_PRIVATE_KEY   pECPrivKey,
    unsigned char*                      pbSecretKey,
    size_t                              cbSecretKey,
    PxCryptLibParamList                 pParamList);

PSECRET
XCRYPTLIBAPI
xCryptLibEllipticCurveAllocateSecret(
    PELLIPTIC_CURVE                 pEllipticCurve,
    PxCryptLibParamList             pParamList);

void
XCRYPTLIBAPI
xCryptLibEllipticCurveFreeSecret(
    PSECRET pSecret);

CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibEllipticCurveDHSecretAgreement(
    const PELLIPTIC_CURVE_PUBLIC_KEY    pPublicKey,
    const PELLIPTIC_CURVE_PRIVATE_KEY   pPrivateKey,
    PSECRET                             pSecret,
    PxCryptLibParamList                 pParamList);

/*
 *  Asymmetric Encryption functions
 * 
*/

struct _RSA_PUBLIC_KEY;
typedef struct _RSA_PUBLIC_KEY* PRSA_PUBLIC_KEY;

size_t
XCRYPTLIBAPI
xCryptLibGetRsaPublicKeyObjectSize(
    size_t bitlen);

size_t
XCRYPTLIBAPI
xCryptLibGetRsaPublicKeyInputBufferSize(
    const PRSA_PUBLIC_KEY pRsaPubKey);

PRSA_PUBLIC_KEY
XCRYPTLIBAPI
xCryptLibAllocateRsaPublicKey(
    size_t              bitlen,
    PxCryptLibParamList pParamList);

CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibInitializeRsaPublicKey(
    PRSA_PUBLIC_KEY         pRsaPublicKey,
    size_t                  bitlen,
    const unsigned char*    pbModulus,
    size_t                  cbModulus,
    const unsigned char*    pbPublicExponent,
    size_t                  cbPublicExponent,
    PxCryptLibParamList     pParamList);

void
XCRYPTLIBAPI
xCryptLibFreeRsaPublicKey(
    PRSA_PUBLIC_KEY     pRsaPubKey);

CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibRsaEncrypt(
    const PRSA_PUBLIC_KEY   pRsaPubKey,
    const unsigned char*    pbInput,
    size_t                  cbInput,
    unsigned char*          pbOutput,
    size_t                  cbOutput,
    PxCryptLibParamList     pParamList);

/// <summary>Verify a digital signature (with appendix) using the RSA algorithm and PKCS#1v1.5 padding.</summary>
/// <param name="pPubKey"> Pointer to the RSA public key. </param>
/// <param name="pbDigest"> Pointer to the message digest to verify against the signature. </param>
/// <param name="cbDigest"> The length of the message digest in bytes. </param>
/// <param name="pbDigestInfo"> The encoded digest info bytes used in PKCS#1v1.5 padding. </param>
/// <param name="cbDigestInfo"> The length of the <paramref name="pbDigestInfo"/> buffer, in bytes. </param>
/// <param name="pbSignature"> The signature to verify. </param>
/// <param name="cbSignature"> The length of <paramref name="pbSignature"/> in bytes. </param>
/// <param name="pParamList"> List of parameters.  May be <c>NULL</c> or empty.</param>
/// <returns> CRYPTO_SUCCESS if verification is successful. </returns>
/// <remarks>
///     For ease of use, the <c>DigestInfo</c> bytes are pre-defined for popular hash functions
///     such as SHA-1, SHA-256, SHA-384, and SHA-512.
///     Typically, the caller would have hashed the message prior to calling this API
///     with a corresponding hash function, such as <see cref="xCryptLibSha1Hash"/>,
///     <see cref="xCryptLibSha256Hash"/>, <see cref="xCryptLibSha384Hash"/>, and <see cref="xCryptLibSha512Hash"/>.
/// </remarks>
/// <seealso cref="SHA1_DIGEST_INFO"/>
/// <seealso cref="SHA1_DIGEST_INFO_LEN"/>
/// <seealso cref="SHA256_DIGEST_INFO"/>
/// <seealso cref="SHA256_DIGEST_INFO_LEN"/>
/// <seealso cref="SHA384_DIGEST_INFO"/>
/// <seealso cref="SHA384_DIGEST_INFO_LEN"/>
/// <seealso cref="SHA512_DIGEST_INFO"/>
/// <seealso cref="SHA512_DIGEST_INFO_LEN"/>
/// <seealso cref="xCryptLibRsaPkcs1VerifySignature"/>
/// \ingroup RSA
CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibRsaPkcs1VerifyHashDigestSignature(
    __in const PRSA_PUBLIC_KEY  pPubKey,
    __in const unsigned char    *pbDigest,
    __in size_t                 cbDigest,
    __in const unsigned char    *pbDigestInfo,
    __in size_t                 cbDigestInfo,
    __in const unsigned char*   pbSignature,
    __in size_t                 cbSignature,
    __in PxCryptLibParamList    pParamList);

/// <summary>Verify a digital signature (with appendix) using the RSA algorithm and PKCS#1v1.5 padding.</summary>
/// <param name="pfHash">Hash function to compute the message digest of the data <paramref name="pbData">. </param>
/// <param name="pRsaPubKey"> Pointer to the RSA public key. </param>
/// <param name="pbData"> Pointer to the message to verify against the signature. </param>
/// <param name="cbData"> The length of the message in bytes. </param>
/// <param name="pbDigest"> Pointer to store the message digest used in verification. </param>
/// <param name="cbDigest"> The length of the message digest in bytes. </param>
/// <param name="pbDigestInfo"> The encoded digest info bytes used in PKCS#1v1.5 padding. </param>
/// <param name="cbDigestInfo"> The length of the <paramref name="pbDigestInfo"/> buffer, in bytes. </param>
/// <param name="pbSignature"> The signature to verify. </param>
/// <param name="cbSignature"> The length of <paramref name="pbSignature"/> in bytes. </param>
/// <param name="pParamList"> List of parameters.  May be <c>NULL</c> or empty.</param>
/// <returns> CRYPTO_SUCCESS if verification is successful. </returns>
/// <remarks>
///     For ease of use, the <paramref name="DigestInfo"/> bytes are pre-defined for popular hash functions
///     such as SHA-1, SHA-256, SHA-384, and SHA-512.
///     Typically, the caller would have hashed the message prior to calling this API
///     with a corresponding hash function, such as <see cref="xCryptLibSha1Hash"/>,
///     <see cref="xCryptLibSha256Hash"/>, <see cref="xCryptLibSha384Hash"/>, and <see cref="xCryptLibSha512Hash"/>.
///     This function computes the message digest and stores it in the <paramref name="pbDigest"> parameter.
///     The caller may use the output digest, if needed.
/// </remarks>
/// <seealso cref="SHA1_DIGEST_INFO"/>
/// <seealso cref="SHA1_DIGEST_INFO_LEN"/>
/// <seealso cref="SHA256_DIGEST_INFO"/>
/// <seealso cref="SHA256_DIGEST_INFO_LEN"/>
/// <seealso cref="SHA384_DIGEST_INFO"/>
/// <seealso cref="SHA384_DIGEST_INFO_LEN"/>
/// <seealso cref="SHA512_DIGEST_INFO"/>
/// <seealso cref="SHA512_DIGEST_INFO_LEN"/>
/// <seealso cref="xCryptLibRsaPkcs1VerifyHashDigestSignature"/>
/// \ingroup RSA
CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibRsaPkcs1VerifySignature(
    __in xCryptHashFn_t                     pfHash,
    __in const PRSA_PUBLIC_KEY              pRsaPubKey,
    __in_bcount(cbData) unsigned char       *pbData,
    __in size_t                             cbData,
    __inout_bcount(cbDigest) unsigned char  *pbDigest,
    __in size_t                             cbDigest,
    __in_bcount(cbDigestInfo) unsigned char *pbDigestInfo,
    __in size_t                             cbDigestInfo,
    __in_bcount(cbSignature) unsigned char  *pbSignature,
    __in size_t                             cbSignature,
    __in PxCryptLibParamList                pParamList);

CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibRsaPkcs1Sha1VerifyHashDigestSignature(
    const PRSA_PUBLIC_KEY   pPubKey,
    const unsigned char     rgbDigest[SHA1_DIGEST_LEN],
    const unsigned char*    pbSignature,
    size_t                  cbSignature,
    PxCryptLibParamList     pParamList);

CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibRsaPkcs1Sha1VerifySignature(
    const PRSA_PUBLIC_KEY   pRsaPubKey,
    const unsigned char*    pbData,
    size_t                  cbData,
    const unsigned char*    pbSignature,
    size_t                  cbSignature,
    PxCryptLibParamList     pParamList);

CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibRsaPkcs1Sha256VerifyHashDigestSignature(
    const PRSA_PUBLIC_KEY   pPubKey,
    const unsigned char     rgbDigest[SHA256_DIGEST_LEN],
    const unsigned char*    pbSignature,
    size_t                  cbSignature,
    PxCryptLibParamList     pParamList);

CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibRsaPkcs1Sha256VerifySignature(
    const PRSA_PUBLIC_KEY   pRsaPubKey,
    const unsigned char*    pbData,
    size_t                  cbData,
    const unsigned char*    pbSignature,
    size_t                  cbSignature,
    PxCryptLibParamList     pParamList);

CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibRsaOaepSha1Encrypt(
    const PRSA_PUBLIC_KEY   pPubKey,
    const unsigned char*    pbInput,
    size_t                  cbInput,
    unsigned char*          pbOutput,
    size_t                  cbOutput,
    PxCryptLibParamList     pParamList);

/*
 *
 * Utilities
 *
 */

/*
    "\x30" //ASN1_SEQUENCE_BYTE = 0x30
    "\x31" //Length of encoding = 13 (length of OID) + 32 (Length of Hash) + 4 (asn1 formatting) = 49 = 0x31
    "\x30" //ASN1_SEQUENCE_BYTE = 0x30
    "\x0D" //Length of the hash function OID 13 bytes = 0x0D
    "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00" // Sha256 OID
    "\x04" //ASN1_OCTET_STRING_BYTE = 0x04  
    "\x20"; // length of SHA256 digest (in bytes) 32 = 0x20
*/

extern unsigned char SHA1_DIGEST_INFO[];
extern size_t SHA1_DIGEST_INFO_LEN;
extern unsigned char SHA256_DIGEST_INFO[];
extern size_t SHA256_DIGEST_INFO_LEN;
extern unsigned char SHA384_DIGEST_INFO[];
extern size_t SHA384_DIGEST_INFO_LEN;
extern unsigned char SHA512_DIGEST_INFO[];
extern size_t SHA512_DIGEST_INFO_LEN;

CRYPTO_BOOL
xCryptLibRsaPkcs1v15CheckSignaturePadding(
    const unsigned char*    pbFormattedBuffer,
    size_t                  cbFormattedBuffer,
    const unsigned char*    pbDigestInfo,
    size_t                  cbDigestInfo,
    size_t                  cbHashDigest);


/*
 *  KDF functions
 * 
*/

/// <summary>
/// Key-derivation function interoperable with CNG. 
/// </summary>
/// Computes <c>F(XCRYPTLIB_PARAM_NAME_KDF_SECRET_PREPEND | Secret | XCRYPTLIB_PARAM_NAME_KDF_SECRET_APPEND)</c>
/// where F is either a hash function or HMAC.  Callers <b>must</b> specify the function to use
/// by setting the parameter <see cref="XCRYPTLIB_PARAM_NAME_KDF_HASH_FUNCTION"/> to one of the 
/// <c>XCRYPT_HASH_NAME_*</c> constants, for example <see cref="XCRYPT_HASH_NAME_HMAC_SHA256"/>
/// or <see cref="XCRYPT_HASH_NAME_SHA256"/>. If an HMAC function is selected, the caller <b>must</b>
/// choose which value is used for the HMAC key, from two options. Either a key value is provided by the 
/// caller with the parameter <see cref="XCRYPTLIB_PARAM_NAME_HMAC_KEY"/>, or the 
/// flag <see cref="XCRYPTLIB_KDF_USE_SECRET_AS_HMAC_KEY_FLAG"/> is set to indicate that <c>Secret</c> 
/// should be used. 
///
///  The number of output bytes is bounded by the chosen hash function's digest length.  For example, 
///  when  <see cref="XCRYPTLIB_PARAM_NAME_KDF_HASH_FUNCTION"/> is <see cref="XCRYPT_HASH_NAME_SHA256"/>
///  only 32 bytes of key material can be generated.  The function will output <c>MIN(cbDerivedKey, n)</c> bytes
///  of key material, where <c>n</c> is the maximum the chosen hash function can produce.  
///  When <c>cbDerviedKey</c> is less than <c>n</c> the first <c>cbDerivedKey</c> bytes of the KDF are output.
///  For a given hash/HMAC function, <c>n</c> can be determined by calling <see cref="xCryptLibKDF_Interop"/> with 
///  <paramref name="pcbResult"/> set to <c>NULL</c>.
///
/// <param name="pSecret"> The secret from which to derive key material.</param>
/// <param name="pbDerivedKey"> Output buffer for the derived key.  If <c>NULL</c> the size 
///    required is output in <paramref name="pcbResult"/>. </param>
/// <param name="cbDerivedKey"> Size of <paramref name="pbDerivedKey"/>, in bytes </param>
/// <param name="pcbResult"> Number of bytes of output. </param>
/// <param name="pParamList"> Parameter list, must not be null, see text above.</param>
/// <returns>
/// <returns> <c>CRYPTO_SUCCESS</c> if a key was successfully derived. </returns>
/// <remarks> 
///  The contents of the output buffer must only be used for cryptographic purposes
///  if the function has returned <c>CRYPTO_SUCCESS</c>. 
/// </remarks>
/// \ingroup KDF
CRYPTO_RESULT
XCRYPTLIBAPI
xCryptLibKDF_Interop(
    const PSECRET       pSecret,
    unsigned char*      pbDerivedKey,
    size_t              cbDerivedKey,
    size_t              *pcbResult,
    PxCryptLibParamList pParamList);

/*
 *
 * Required Callbacks
 *
 */

/// <summary>
///     User-defined memory allocation function required for xCrypt. 
/// <summary>
/// <param name="cb"> Number of bytes to allocate. </param>
/// <returns>
///     A pointer to <paramref name="cb"/> bytes of allocated memory, 
///     or <c>NULL</c> if allocation fails.
/// </returns>
/// <seealso cref="xCryptFree"/>
/// \ingroup CB
void* XCRYPTLIBAPI xCryptAlloc( size_t cb );

/// <summary>
///     User-defined memory free function required for xCrypt. 
/// <summary>
/// <param name="pv"> Pointer to memory allocated with <see cref="xCryptAlloc"/> to be freed. </param>
/// <seealso cref="xCryptAlloc"/>
/// \ingroup CB
void XCRYPTLIBAPI xCryptFree( void *pv );

/// <summary>
///     User-defined function to generate random bytes, required for xCrypt. 
/// <summary>
/// <param name="pb"> Pointer to memory that recives random data. </param>
/// <param name="cb"> Number of bytes to write in <paramref name="pb"/>. </param>
/// <seealso cref="xCryptAlloc"/>
/// <returns>
///     CRYPTO_TRUE if <paramref name="cb"/> random bytes were written to <paramref name="pb"/>. 
///     CRYPTO_FALSE if random number generation failed.
/// </returns>
/// <remarks>
///     Callers must check the return value, and only use the output for cryptographic
///     purposes if CRYPTO_TRUE was returned. 
/// </remarks>
/// \ingroup CB
CRYPTO_BOOL XCRYPTLIBAPI xCryptRandom(unsigned char* pb, size_t cb);

#ifdef __cplusplus
}
#endif

#endif /*__XCRYPTLIB_H__*/