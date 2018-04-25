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

#import "XCTestCase+TestHelperMethods.h"

#import "ADTokenCacheTestUtil.h"

#import "ADTokenCache+Internal.h"
#import "ADTokenCacheItem.h"
#import "ADTokenCacheKey.h"

#if TARGET_OS_IPHONE
#import "ADKeychainTokenCache+Internal.h"
#endif

static ADTokenCacheItem *getToken(id<ADTokenCacheDataSource> tokenCache, NSString *authority, NSString *clientId, NSString *resource)
{
    ADTokenCacheKey *key = [ADTokenCacheKey keyWithAuthority:authority resource:resource clientId:clientId error:nil];
    return [tokenCache getItemsWithKey:key userId:TEST_USER_ID correlationId:TEST_CORRELATION_ID error:nil].firstObject;
}

static ADTokenCacheItem *getMRRT(id<ADTokenCacheDataSource> tokenCache, NSString *authority)
{
    return getToken(tokenCache, authority, TEST_CLIENT_ID, nil);
}

static ADTokenCacheItem *getFRT(id<ADTokenCacheDataSource> tokenCache, NSString *authority)
{
    return getToken(tokenCache, authority, @"foci-1", nil);
}

static ADTokenCacheItem *getAT(id<ADTokenCacheDataSource> tokenCache, NSString *authority)
{
    return getToken(tokenCache, authority, TEST_CLIENT_ID, TEST_RESOURCE);
}

@implementation ADTokenCache (TestUtil)

@dynamic macTokenCache;

- (NSString *)getAT:(NSString *)authority
{
    return getAT(self, authority).accessToken;
}

- (NSString *)getMRRT:(NSString *)authority
{
    return getMRRT(self, authority).refreshToken;
}

- (ADTokenCacheItem *)getMRRTItem:(NSString *)authority
{
    return getMRRT(self, authority);
}

- (NSString *)getFRT:(NSString *)authority
{
    return getFRT(self, authority).refreshToken;
}

- (ADTokenCacheItem *)getFRTItem:(NSString *)authority
{
    return getFRT(self, authority);
}

@end

#if TARGET_OS_IPHONE
@implementation ADLegacyKeychainTokenCache (TestUtil)

- (NSString *)getAT:(NSString *)authority
{
    return getAT(self, authority).accessToken;
}

- (NSString *)getMRRT:(NSString *)authority
{
    return getMRRT(self, authority).refreshToken;
}

- (ADTokenCacheItem *)getMRRTItem:(NSString *)authority
{
    return getMRRT(self, authority);
}

- (NSString *)getFRT:(NSString *)authority
{
    return getFRT(self, authority).refreshToken;
}

- (ADTokenCacheItem *)getFRTItem:(NSString *)authority
{
    return getFRT(self, authority);
}

@end
#endif
