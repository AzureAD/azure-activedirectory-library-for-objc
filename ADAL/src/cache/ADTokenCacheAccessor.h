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
#import "ADTokenCacheDataSource.h"

@interface ADTokenCacheAccessor : NSObject
{
    id<ADTokenCacheDataSource> _dataSource;
    NSString * _authority;
}

- (id<ADTokenCacheDataSource>)dataSource;

- (id)initWithDataSource:(id<ADTokenCacheDataSource>)dataSource
               authority:(NSString *)authority;

/*!
    Returns a AT/RT Token Cache Item for the given parameters. The RT in this item will only be good
    for the given resource. If no RT is returned in the item then a MRRT or FRT should be used (if
    available).
  */
- (ADTokenCacheItem *)getATRTItemForUser:(ADUserIdentifier *)identifier
                                resource:(NSString *)resource
                                clientId:(NSString *)clientId
                                 request:(ADAuthenticationRequest*)request
                                   error:(ADAuthenticationError * __autoreleasing *)error;

/*!
    Returns a Multi-Resource Refresh Token (MRRT) Cache Item for the given parameters. A MRRT can
    potentially be used for many resources for that given user, client ID and authority.
 */
- (ADTokenCacheItem *)getMRRTItemForUser:(ADUserIdentifier *)identifier
                                clientId:(NSString *)clientId
                                 request:(ADAuthenticationRequest*)request
                                   error:(ADAuthenticationError * __autoreleasing *)error;

/*!
    Returns a Family Refresh Token for the given authority, user and family ID, if available. A FRT can
    be used for many resources within a given family of client IDs.
 */
- (ADTokenCacheItem *)getFRTItemForUser:(ADUserIdentifier *)identifier
                               familyId:(NSString *)familyId
                                request:(ADAuthenticationRequest*)request
                                  error:(ADAuthenticationError * __autoreleasing *)error;

/*!
    ADFS is not capable of giving us an idtoken when we authenticate users, so we don't know who got logged
    in or who to cache the tokens for, and instead put the token in a special entry.
 */
- (ADTokenCacheItem*)getADFSUserTokenForResource:(NSString *)resource
                                        clientId:(NSString *)clientId
                                         request:(ADAuthenticationRequest*)request
                                           error:(ADAuthenticationError * __autoreleasing *)error;

/*!
 Stores the result in the cache. cacheItem parameter may be nil, if the result is successfull and contains
 the item to be stored.
 
 @param result       The result to update the cache to
 @param refreshToken The refresh token (if anything) that was used to get this authentication result
 */
- (void)updateCacheToResult:(ADAuthenticationResult *)result
                  cacheItem:(ADTokenCacheItem *)cacheItem
               refreshToken:(NSString *)refreshToken
                    request:(ADAuthenticationRequest*)request;

@end
