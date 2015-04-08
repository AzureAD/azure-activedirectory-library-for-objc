// Copyright © Microsoft Open Technologies, Inc.
//
// All Rights Reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
// ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
// PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
//
// See the Apache License, Version 2.0 for the specific language
// governing permissions and limitations under the License.


#import "ADBrokerCryptoHelper.h"

@implementation ADBrokerCryptoHelper

typedef struct _SECRET
{
    size_t      cbObject;
    CRYPTO_BOOL fHeapAllocated;
    size_t      cbSecret;
} SECRET;


void* XCRYPTLIBAPI xCryptAlloc( size_t cb )
{
    return malloc(cb);
}

void XCRYPTLIBAPI xCryptFree( void *pv )
{
    free(pv);
}


CRYPTO_BOOL XCRYPTLIBAPI xCryptRandom(unsigned char* pb, size_t cb)
{
int rv = 0;
// TODO: This code hasn't been built/tested on iOS yet.

rv = SecRandomCopyBytes(kSecRandomDefault, cb, (uint8_t*) pb);
if(rv != 0)
{
    return CRYPTO_FALSE;
}

return CRYPTO_TRUE;
}


CRYPTO_RESULT
MakeXCryptLibSecret(
                    PSECRET  *ppSecret,
                    unsigned char*  pbSecret,
                    size_t          cbSecret)
{
    SECRET   *pSecret = NULL;
    
    unsigned char*  pbAllocation = NULL;
    
    size_t  cbObject = 0;
    
    CRYPTO_RESULT error = CRYPTO_ERROR_UNKNOWN;
    
    cbObject = sizeof(SECRET) + cbSecret;
    
    pbAllocation = (unsigned char*)malloc(cbObject);
    if (NULL == pbAllocation)
    {
        goto Cleanup;
    }
    
    pSecret = (SECRET*)pbAllocation;
    
    pSecret->cbObject = cbObject;
    pSecret->fHeapAllocated = CRYPTO_TRUE;
    pSecret->cbSecret = cbSecret;
    
    memcpy( pbAllocation+sizeof(SECRET),
           pbSecret,
           cbSecret);
    
    *ppSecret = pSecret;
    pSecret = NULL;
    
    error = CRYPTO_SUCCESS;
    
Cleanup:
    
    if(pSecret)
    {
        free(pSecret);
    }
    
    return error;
}

CRYPTO_RESULT DoKDFUsingxCryptLib(
                                  unsigned char*  pbLabel,
                                  unsigned long   cbLabel,
                                  unsigned char*  pbCtx,
                                  unsigned long   cbCtx,
                         unsigned char*  pbKey,
                         unsigned long   cbKey,
                         unsigned char*  pbDerivedKey,
                         unsigned long   cbDerivedKey
                         )
{
    CRYPTO_RESULT           Status;
    PxCryptLibParamList     pParameterList = NULL;
    xCryptLibParamList      ParameterList = {0};
    xCryptLibParamBuffer    rgBuffers[6];
    
    PSECRET                 pSecret = NULL;
    
    size_t                  cBuffers = 0;
    size_t                  cbResult;
    
    unsigned long           dwFlags = 0;
    unsigned long           dwLocalFlags = 0;
    
    dwLocalFlags |= XCRYPTLIB_KDF_SP800_108_FLAG;
    
    rgBuffers[cBuffers].pwszBufferType = XCRYPTLIB_PARAM_NAME_FLAGS;
    rgBuffers[cBuffers].pvBuffer = (void*)&dwLocalFlags;
    rgBuffers[cBuffers].cbBuffer = sizeof(unsigned long);
    
    cBuffers++;
    
    // If explicit HMAC key is provided then setup a parameter buffer for it
    if ((dwFlags & XCRYPTLIB_KDF_USE_SECRET_AS_HMAC_KEY_FLAG) == 0)
    {
        if (pbKey == NULL)
        {
            // Expected an HMAC key either as parameter or by using
            // the USE_SECRET_AS_HMAC_KEY flag, exit with an error
            Status = CRYPTO_ERROR_INVALID_PARAMETER;
            goto cleanup;
        }
        
        rgBuffers[cBuffers].pwszBufferType = XCRYPTLIB_PARAM_NAME_HMAC_KEY;
        rgBuffers[cBuffers].pvBuffer = (void*)pbKey;
        rgBuffers[cBuffers].cbBuffer = cbKey;
        
        cBuffers++;
    }
    
    rgBuffers[cBuffers].pwszBufferType = XCRYPTLIB_PARAM_NAME_KDF_HASH_FUNCTION;
    rgBuffers[cBuffers].pvBuffer = XCRYPT_HASH_NAME_SHA256;
    rgBuffers[cBuffers].cbBuffer = sizeof(XCRYPT_HASH_NAME_SHA256);
    cBuffers++;
    
    rgBuffers[cBuffers].pwszBufferType = XCRYPTLIB_PARAM_NAME_KDF_SP800_108_LABEL;
    rgBuffers[cBuffers].pvBuffer = (void*)pbLabel;
    rgBuffers[cBuffers].cbBuffer = cbLabel;
    cBuffers++;
    
    rgBuffers[cBuffers].pwszBufferType = XCRYPTLIB_PARAM_NAME_KDF_SP800_108_CONTEXT;
    rgBuffers[cBuffers].pvBuffer = (void*)pbCtx;
    rgBuffers[cBuffers].cbBuffer = cbCtx;
    cBuffers++;
    
    // Setup parameters
    ParameterList.ulVersion = XCRYPTLIBBUFFER_VERSION;
    ParameterList.cBuffers = cBuffers;
    ParameterList.pBuffers = rgBuffers;
    pParameterList = &ParameterList;
    
    Status = MakeXCryptLibSecret(   &pSecret,
                                 pbKey,
                                 cbKey);
    if (CRYPTO_SUCCESS != Status)
    {
        goto cleanup;
    }
    
    Status = xCryptLibKDF_Interop(
                                  pSecret,
                                  pbDerivedKey,
                                  cbDerivedKey,
                                  &cbResult,
                                  pParameterList);
    
    
    
    if (Status != CRYPTO_SUCCESS)
    {
        goto cleanup;
    }
    
    if (cbResult != cbDerivedKey)
    {
        Status = CRYPTO_ERROR_UNKNOWN;
        goto cleanup;
    }
    
cleanup:
    return Status;
}


@end
