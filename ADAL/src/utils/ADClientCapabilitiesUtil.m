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

#import "ADClientCapabilitiesUtil.h"
#import "NSDictionary+MSIDExtensions.h"

static NSString *kAccessTokenClaims = @"access_token";
static NSString *kCapabilitiesClaims = @"xms_cc";
static NSString *kValuesClaim = @"values";

@implementation ADClientCapabilitiesUtil

+ (NSString *)claimsParameterFromCapabilities:(NSArray<NSString *> *)capabilities
{
    if (![capabilities count])
    {
        return nil;
    }

    NSDictionary *claims = @{kAccessTokenClaims:@{kCapabilitiesClaims: @{kValuesClaim : capabilities}}};
    return [self jsonFromCapabilities:claims];
}

+ (NSString *)claimsParameterFromCapabilities:(NSArray<NSString *> *)capabilities
                              developerClaims:(NSDictionary *)developerClaims
{
    if (![capabilities count])
    {
        return [self jsonFromCapabilities:developerClaims];
    }

    NSMutableDictionary *claims = [NSMutableDictionary new];

    if (developerClaims)
    {
        [claims addEntriesFromDictionary:developerClaims];
    }

    NSDictionary *additionalClaims = @{kCapabilitiesClaims: @{kValuesClaim : capabilities}};
    NSDictionary *accessTokenClaims = claims[kAccessTokenClaims];

    if ([accessTokenClaims count])
    {
        NSMutableDictionary *mutableAccessTokenClaims = [accessTokenClaims mutableCopy];
        [mutableAccessTokenClaims addEntriesFromDictionary:additionalClaims];
        claims[kAccessTokenClaims] = mutableAccessTokenClaims;
    }
    else
    {
        claims[kAccessTokenClaims] = additionalClaims;
    }

    return [self jsonFromCapabilities:claims];
}

+ (NSString *)jsonFromCapabilities:(NSDictionary *)capabilities
{
    if (!capabilities)
    {
        return nil;
    }

    NSError *error = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:capabilities options:0 error:&error];

    if (!jsonData)
    {
        MSID_LOG_ERROR(nil, @"Failed to convert capabilities into JSON");
        MSID_LOG_ERROR_PII(nil, @"Failed to convert capabilities into JSON with error %@", error.description);
        return nil;
    }

    return [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
}

@end
