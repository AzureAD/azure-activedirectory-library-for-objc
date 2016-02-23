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

@class ADKeyChainHelper;
@class ADTokenCacheItem;
@class ADAuthenticationError;

@interface ADKeychainTokenCache : NSObject

@property (readonly) NSString* __nonnull sharedGroup;

/* Initializes the token cache store with default shared group value.
 */
- (nullable instancetype)init;

/*! Initializes the token cache store.
 @param: sharedGroup: Optional. If the application needs to share the cached tokens
 with other applications from the same vendor, the app will need to specify the 
 shared group here and add the necessary entitlements to the application.
 See Apple's keychain services documentation for details. */
- (nullable instancetype)initWithGroup:(nullable NSString *)sharedGroup;

/*! Return a copy of all items. The array will contain ADTokenCacheItem objects,
 containing all of the cached information. Returns an empty array, if no items are found.
 Returns nil in case of error. */
- (nullable NSArray<ADTokenCacheItem *> *)allItems:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error;

- (BOOL)removeItem:(nonnull ADTokenCacheItem *)item
             error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error;

- (BOOL)removeAllForClientId:(NSString * __nonnull)clientId
                       error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error;

- (BOOL)removeAllForUserId:(NSString * __nonnull)userId
                      clientId:(NSString * __nonnull)clientId
                         error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error;

@end