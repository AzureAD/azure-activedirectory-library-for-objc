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


#import "ADTestUtils.h"
#import <ADALiOS/ADProfileInfo.h>
#import <ADALiOS/ADAuthenticationError.h>
#import <ADALiOS/ADTokenCacheStoreItem.h>
#import <ADALiOS/ADTokenCacheStoreKey.h>

static NSString* const s_profileHeader = @"{\"typ\":\"JWT\",\"alg\":\"none\"}";

@implementation ADTestUtils

+ (ADTestUtils*)defaultUtils
{
    return [[ADTestUtils alloc] init];
}

- (id)init
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _profileVersion = @"1.0";
    _username = @"barbara@contoso.com";
    _subject = @"0DxnAlLi12IvGL_dG3dDMk3zp6AQHnjgogyim5AWpSc";
    _friendlyName = @"Barbara Sankovic";
    _tid = @"6fd1f5cd-a94c-4335-889b-6c598e6d8048";
    
    // This "extra_claim" fields is to verify that any claim that gets passed in the JSON
    // object will end up in the allClaims dictionary
    _extra_claim = @"asdhbkajdsfhoasildfjksudjhlsdkfjailskjdfal;skjdkuajhsbfnklsad";
    
    _authority = @"https://login.windows.net/sometenant.com";
    _clientId = @"client id";
    _accessToken = @"access token";
    _accessTokenType = @"access token type";
    _refreshToken = @"refresh token";
    _expiresOn = [NSDate dateWithTimeIntervalSinceNow:3600];
    
    _scopes = @[@"mail.read", @"planetarydefense.target.acquire", @"planetarydefense.fire"];
    return self;
}

- (NSString*)rawProfileInfo
{
    NSDictionary* claimsDict = @{@"ver" : _profileVersion,
                                 @"tid" : _tid,
                                 @"preferred_username" : _username,
                                 @"sub" : _subject,
                                 @"name" : _friendlyName,
                                 @"extra_claim" : _extra_claim,};
    NSString* claims = [[NSJSONSerialization dataWithJSONObject:claimsDict options:0 error:nil] base64EncodedStringWithOptions:0];
    return [NSString stringWithFormat:@"%@.%@", [s_profileHeader adBase64UrlEncode], claims];
}

#define VERIFY_PROPERTY(_property) \
    if (![[self _property] isEqual:[profileInfo _property]]) { \
        if (errorDetails) { \
            *errorDetails = [NSString stringWithFormat:@"property \"%s\" does not match in %s", #_property, __PRETTY_FUNCTION__]; \
        } \
        return nil; \
    }

#define VERIFY_CLAIM(_claim) \
    if (![[self _claim] isEqualToString:[[profileInfo allClaims] objectForKey:@#_claim]]) { \
        if (errorDetails) { \
            *errorDetails = [NSString stringWithFormat:@"claim \"%s\" does not match in %s", #_claim, __PRETTY_FUNCTION__]; \
        } \
        return nil; \
    }

- (ADProfileInfo*)createProfileInfo:(NSString* __autoreleasing *)errorDetails
{
    NSString* profile_info = [self rawProfileInfo];
    ADAuthenticationError* error = nil;
    ADProfileInfo* profileInfo = [ADProfileInfo profileInfoWithEncodedString:profile_info error:&error];
    if (!profileInfo)
    {
        if (errorDetails)
        {
            *errorDetails = error.errorDetails;
        }
        return nil;
    }
    
    VERIFY_PROPERTY(username);
    VERIFY_PROPERTY(subject);
    VERIFY_PROPERTY(friendlyName);
    VERIFY_PROPERTY(rawProfileInfo);
    
    VERIFY_CLAIM(tid);
    VERIFY_CLAIM(extra_claim);
    
    return profileInfo;
}

//values
- (ADTokenCacheStoreItem*)createCacheItem:(NSString* __autoreleasing *)errorDetails
{
    ADProfileInfo* profileInfo = [self createProfileInfo:errorDetails];
    if (!profileInfo)
    {
        return nil;
    }
    
    ADTokenCacheStoreItem* item = [[ADTokenCacheStoreItem alloc] init];
    //item.resource = @"resource";
    item.scopes = [NSSet setWithArray:_scopes];
    item.authority = _authority;
    item.clientId = _clientId;
    item.accessToken = _accessToken;
    item.refreshToken = _refreshToken;
    item.sessionKey = nil;
    item.policy = _policy;
    //1hr into the future:
    item.expiresOn = _expiresOn;
    item.profileInfo = profileInfo;
    item.accessTokenType = _accessTokenType;
    return item;
}

- (ADTokenCacheStoreKey*)createKey
{
    return [ADTokenCacheStoreKey keyWithAuthority:_authority
                                         clientId:_clientId
                                           userId:_username
                                         uniqueId:_subject
                                           idType:RequiredDisplayableId
                                           policy:_policy
                                           scopes:[NSSet setWithArray:_scopes]
                                            error:nil];
}

@end
