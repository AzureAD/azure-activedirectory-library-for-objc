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

@class ADAuthenticationError;
@class ADClientMetrics;

/*! The completion block declaration. */
typedef void(^ADDiscoveryCallback)(BOOL validated, ADAuthenticationError* error);


/*! A singleton class, used to validate authorities with in-memory caching of the previously validated ones.
 The class is thread-safe. */
@interface ADInstanceDiscovery : NSObject
{
    NSMutableSet* _validatedAuthorities;
}

@property (readonly) NSSet* validatedAuthorities;

/*! The shared instance of the class.*/
+ (ADInstanceDiscovery *)sharedInstance;

/*! Validates asynchronously the provided authority. Caches the validations in in-memory cache.
 @param authority: the authority to be validated. ADFS authority instances cannot be validated.
 @param correlationId: a special UUID sent out with the validation request. This UUID can be useful in case
 of calling support to track unexpected failures. This parameter may be null, in which case the method will generate a new UUID.
 @param completionBlock: the block to be called when the result is achieved.*/
- (void)validateAuthority:(NSString *)authority
            requestParams:(ADRequestParameters*)requestParams
          completionBlock:(ADDiscoveryCallback) completionBlock;

/*! Takes the string and makes it canonical URL, e.g. lowercase with
 ending trailing "/". If the authority is not a valid URL, the method
 will return nil. */
+ (NSString*)canonicalizeAuthority:(NSString *)authority;

- (NSString*)extractHost:(NSString *)authority
           correlationId:(NSUUID *)correlationId
                   error:(ADAuthenticationError * __autoreleasing *)error;
- (BOOL)isAuthorityValidated:(NSString *)authorityHost;
- (BOOL)addValidAuthority:(NSString *)authorityHost;

- (void)requestValidationOfAuthority:(NSString *)authority
                                host:(NSString *)authorityHost
                    trustedAuthority:(NSString *)trustedAuthority
                       requestParams:(ADRequestParameters*)requestParams
                     completionBlock:(ADDiscoveryCallback)completionBlock;


@end
