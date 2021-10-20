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

#import "ADALKeychainTokenCache.h"
#import "ADALTokenCacheDataSource.h"

@class ADKeyChainHelper;
@class ADALTokenCacheItem;
@class ADALAuthenticationError;

@interface ADLegacyKeychainTokenCache : ADALKeychainTokenCache <ADALTokenCacheDataSource>

@property (readonly) NSString* __nonnull sharedGroup;

/*!
     The name of the keychain group to be used by default when creating an ADALAuthenticationContext,
     the default value is com.microsoft.adalcache.
 */
+ (nullable NSString*)defaultKeychainGroup;

/*!
     Set the default keychain sharing group to use with ADAL. If set to 'nil' the main bundle's
     identifier will be used instead. Any keychain sharing group other then the main bundle's identifier
     will require a keychain sharing group entitlement.
 
     See apple's documentation for keychain groups: such groups require certain
     entitlements to be set by the applications. Additionally, access to the items in this group
     is only given to the applications from the same vendor. If this property is not set, the behavior
     will depend on the values in the entitlements file (if such exists) and may not result in token
     sharing. The property has no effect if other cache mechanisms are used (non-keychain).

 
     NOTE: Once an authentication context has been created with the default keychain
     group, or +[ADALKeychainTokenCache defaultKeychainCache] has been called then
     this value cannot be changed. Doing so will throw an exception.
 */
+ (void)setDefaultKeychainGroup:(nullable NSString*)keychainGroup;

/*!
    @return A singleton instance of the ADALKeychainTokenCache for the default keychain group.
 */
+ (nonnull ADLegacyKeychainTokenCache*)defaultKeychainCache;

/*!
    @return An instance of ADALKeychainTokenCache for the given group, or the defaultKeychainCache
            singleton if the default keychain group is passed in.
 */
+ (nonnull ADLegacyKeychainTokenCache*)keychainCacheForGroup:(nullable NSString*)group;

/* Initializes the token cache store with default shared group value.
 */
- (nonnull instancetype)init;

/*! Initializes the token cache store.
 @param sharedGroup Optional. If the application needs to share the cached tokens
 with other applications from the same vendor, the app will need to specify the 
 shared group here and add the necessary entitlements to the application.
 See Apple's keychain services documentation for details. */
- (nullable instancetype)initWithGroup:(nullable NSString *)sharedGroup;

/*! Return a copy of all items. The array will contain ADALTokenCacheItem objects,
 containing all of the cached information. Returns an empty array, if no items are found.
 Returns nil in case of error. */
- (nullable NSArray<ADALTokenCacheItem *> *)allItems:(ADALAuthenticationError * __nullable __autoreleasing * __nullable)error;

/* Removes a token cache item from the keychain */
- (BOOL)removeItem:(nonnull ADALTokenCacheItem *)item
             error:(ADALAuthenticationError * __nullable __autoreleasing * __nullable)error;

/* Removes all token cache items for a specific client from the keychain.
 */
- (BOOL)removeAllForClientId:(NSString * __nonnull)clientId
                       error:(ADALAuthenticationError * __nullable __autoreleasing * __nullable)error;

/* Removes all token cache items for a specific user and a specific clientId from the keychain
 */
- (BOOL)removeAllForUserId:(NSString * __nonnull)userId
                  clientId:(NSString * __nonnull)clientId
                     error:(ADALAuthenticationError * __nullable __autoreleasing * __nullable)error;

/*
   Removes all token cache items for a specific user from the keychain with
   either com.microsoft.adalcache shared group by default or the one provided in setDefaultKeychainGroup method.
 
   This is a destructive action and will remove the SSO state from all apps sharing the same cache!
   It's indended to be used only as a way to achieve GDPR compliance and make sure all user artifacts are cleaned on user sign out.
   It's not indended to be used as a way to reset or fix token cache.
 */
- (BOOL)wipeAllItemsForUserId:(NSString * __nonnull)userId
                        error:(ADALAuthenticationError * __nullable __autoreleasing * __nullable)error;

// Internal methods
+ (BOOL)checkStatus:(OSStatus)status
          operation:(nullable NSString *)operation
      correlationId:(nullable NSUUID *)correlationId
              error:(ADALAuthenticationError * __nullable __autoreleasing * __nullable)error;

- (nullable NSMutableDictionary *)queryDictionaryForKey:(nullable ADALTokenCacheKey *)key
                                                 userId:(nullable NSString *)userId
                                             additional:(nullable NSDictionary*)additional;

- (nullable NSString*)keychainKeyFromCacheKey:(nullable ADALTokenCacheKey *)itemKey;

/*! This method should *only* be called in test code, it should never be called
 in production code */
- (void)testRemoveAll:(ADALAuthenticationError * __nullable __autoreleasing * __nullable)error;

- (nullable NSDictionary*)defaultKeychainQuery;

@end
