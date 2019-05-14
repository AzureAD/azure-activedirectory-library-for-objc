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

@class ADTokenCacheKey;
@class ADTokenCacheItem;
@class ADAuthenticationError;

@protocol ADTokenCacheDataSource <NSObject>

/*!
 @param key      The key of the item.
 @param userId   The specific user whose item is needed. May be nil, in which
 case the item for the first user in the cache will be returned.
 @param error    Will be set only in case of ambiguity. E.g. if userId is nil
 and we have tokens from multiple users. If the cache item is not
 present, the error will not be set.
 */
- (nullable ADTokenCacheItem *)getItemWithKey:(nonnull ADTokenCacheKey *)key
                                       userId:(nullable NSString *)userId
                                correlationId:(nullable NSUUID *)correlationId
                                        error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error;

/*!
 @param key      The key of the item. May be nil, in which case all items that match
 other parameters will be returned.
 @param userId   The specific user whose item is needed. May be nil, in which
 case the item for the first user in the cache will be returned.
 @param error    Will be set only in case of ambiguity. E.g. if userId is nil
 and we have tokens from multiple users. If the cache item is not
 present, the error will not be set.
 */
- (nullable NSArray <ADTokenCacheItem *> *)getItemsWithKey:(nullable ADTokenCacheKey *)key
                                                    userId:(nullable NSString *)userId
                                             correlationId:(nullable NSUUID * )correlationId
                                                     error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error;

/*!
 Ensures the cache contains an item matching the passed in item, adding or updating the
 item as necessary.
 
 @param  item    The item to add to the cache, or update if an item matching the key and
 userId already exists in the cache.
 @param  error   (Optional) In the case of an error this will be filled with the
 error details.
 */
- (BOOL)addOrUpdateItem:(nonnull ADTokenCacheItem *)item
          correlationId:(nullable NSUUID *)correlationId
                  error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error;

/*!
 @param  item    The item to remove from the cache
 @param  error   (Optional) In the case of an error this will be filled with the
 error details.
 
 @return YES if the item was successfully removed, or was not in the cache. If NO
 look
 */
- (BOOL)removeItem:(nonnull ADTokenCacheItem *)item
             error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error;

- (nullable NSArray*)allItems:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error;

/* Removes all token cache items for a specific client from the keychain.
 */
- (BOOL)removeAllForClientId:(NSString * __nonnull)clientId
                       error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error;

/* Removes all token cache items for a specific user and a specific clientId from the keychain
 */
- (BOOL)removeAllForUserId:(NSString * __nonnull)userId
                  clientId:(NSString * __nonnull)clientId
                     error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error;

/*
 Removes all token cache items for a specific user from the keychain with
 either com.microsoft.adalcache shared group by default or the one provided in setDefaultKeychainGroup method.
 
 This is a destructive action and will remove the SSO state from all apps sharing the same cache!
 It's indended to be used only as a way to achieve GDPR compliance and make sure all user artifacts are cleaned on user sign out.
 It's not indended to be used as a way to reset or fix token cache.
 */
- (BOOL)wipeAllItemsForUserId:(NSString * __nonnull)userId
                        error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error;

/*!
 Returns any information present about last application, who wiped tokens, if present.
 */
- (nullable NSDictionary *)getWipeTokenData;

@end
