// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import "ADAuthenticationError.h"
#import "ADErrorCodes.h"
#import "ADTokenCacheItem.h"
#import "MSIDError.h"

#define AUTH_ERROR(_CODE, _DETAILS, _CORRELATION) \
    NSError *adError = MSIDCreateError(ADAuthenticationErrorDomain, _CODE, _DETAILS, nil, nil, nil, _CORRELATION, nil); \
    if (error) { *error = adError; }



#define AUTH_ERROR_RETURN_IF_NIL(_VAL, _CODE, _DETAILS, _CORRELATION) \
    if (_VAL == nil) { \
        AUTH_ERROR(_CODE, _DETAILS, _CORRELATION); \
        return nil; \
    }

#define ARG_RETURN_IF_NIL(_ARG, _CORRELATION) \
    if (_ARG == nil) { \
        AUTH_ERROR(AD_ERROR_DEVELOPER_INVALID_ARGUMENT, @#_ARG " should not be nil.", _CORRELATION); \
        return nil; \
    }

@interface ADAuthenticationError (Internal)

//////////////////

+ (ADAuthenticationError *)errorWithNSError:(NSError *)error;

+ (ADAuthenticationError *)errorWithDomain:(NSString *)domain
                                      code:(NSInteger)code
                          errorDescription:(NSString *)errorDescription
                                oauthError:(NSString *)oauthError
                                  subError:(NSString *)subError
                           underlyingError:(NSError *)underlyingError
                             correlationId:(NSUUID *)correlationId
                                  userInfo:(NSDictionary *)userInfo;

//////////////////
/*
    Returns string representation of ADErrorCode or error code number as string, if mapping for that error is missing
 */
+ (NSString*)stringForADErrorCode:(ADErrorCode)code;

@end

