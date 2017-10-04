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

/*! Defines the cache store key. The object is immutable and new one should be created each time
 a new key is required. Keys can be created or extracted from existing ADTokenCacheItem objects. */
@interface ADTokenCacheKey : NSObject <NSCopying, NSSecureCoding>
{
    NSUInteger _hash;
    NSString* _authority;
    NSString* _resource;
    NSString* _clientId;
}

/*! Creates a key
 @param authority Required. The authentication authority used.
 @param resource Optional. The resource used for the token. Multi-resource refresh token items can be extracted by specifying nil.
 @param clientId Optional, can be nil. The client identifier
 */
+ (ADTokenCacheKey *)keyWithAuthority:(NSString *)authority
                             resource:(NSString *)resource
                             clientId:(NSString *)clientId
                                error:(ADAuthenticationError * __autoreleasing *)error;

/*! The authority that issues access tokens */
@property (readonly) NSString* authority;

/*! The resouce to which the access tokens are issued. May be nil in case of multi-resource refresh token. */
@property (readonly) NSString* resource;

/*! The application client identifier */
@property (readonly) NSString* clientId;

- (ADTokenCacheKey *)mrrtKey;


@end
