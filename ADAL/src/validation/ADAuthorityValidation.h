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


#import <Foundation/Foundation.h>

@class ADAuthorityValidationResponse;
@class MSIDAadAuthorityCache;

/*! The completion block declaration. */
typedef void(^ADAuthorityValidationCallback)(BOOL validated, ADAuthenticationError *error);

/*! A singleton class, used to validate authorities with in-memory caching of the previously validated ones.
 The class is thread-safe. */
@interface ADAuthorityValidation : NSObject
{
    MSIDAadAuthorityCache *_aadCache;
}

@property (readonly) MSIDAadAuthorityCache *aadCache;

+ (ADAuthorityValidation *)sharedInstance;

/*!
 This is for caching of valid authorities.
 For ADFS, it will cache the authority and the domain. 
 For AAD, it will simply cache the authority
 */
// Cache - ADFS
- (BOOL)addValidAuthority:(NSURL *)authority domain:(NSString *)domain;
- (BOOL)isAuthorityValidated:(NSURL *)authority domain:(NSString *)domain;
// Cache - AAD

/*!
 Checks an authority.
 For AAD, if metadata exists for an endpoint, we’ll want to retrieve that regardless of
 whether authority validation is turned on.
 
 @param requestParams        Request parameters
 @param validateAuthority    authority validation check
 @param completionBlock      The block to execute upon completion.
 
 */
- (void)checkAuthority:(ADRequestParameters*)requestParams
     validateAuthority:(BOOL)validateAuthority
       completionBlock:(ADAuthorityValidationCallback)completionBlock;

- (void)addInvalidAuthority:(NSString *)authority;

- (NSURL *)networkUrlForAuthority:(NSURL *)authority
                          context:(id<MSIDRequestContext>)context;
- (NSURL *)cacheUrlForAuthority:(NSURL *)authority
                        context:(id<MSIDRequestContext>)context;
- (NSArray<NSURL *> *)cacheAliasesForAuthority:(NSURL *)authority;

@end


