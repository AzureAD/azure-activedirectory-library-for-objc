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

#import "ADALKeychainUtil.h"

@implementation ADALKeychainUtil

+ (NSString*)keychainTeamId:(ADALAuthenticationError* __autoreleasing *)error
{
    static dispatch_once_t s_once;
    static NSString* s_keychainTeamId = nil;
    
    static ADALAuthenticationError* adError = nil;
    
    dispatch_once(&s_once, ^{
        ADALAuthenticationError* localError = nil;
        s_keychainTeamId = [self retrieveTeamIDFromKeychain:&localError];
        adError = localError;
        MSID_LOG_INFO_PII(nil, @"Using \"%@\" Team ID for Keychain.", s_keychainTeamId);
    });
    
    if (!s_keychainTeamId && error)
    {
        *error = adError;
    }
    
    return s_keychainTeamId;
}

+ (NSString*)retrieveTeamIDFromKeychain:(ADALAuthenticationError * __autoreleasing *)error
{
    NSDictionary *query = @{ (id)kSecClass : (id)kSecClassGenericPassword,
                             (id)kSecAttrAccount : @"SDK.ObjC.teamIDHint",
                             (id)kSecAttrService : @"",
                             (id)kSecReturnAttributes : @YES };
    CFDictionaryRef result = nil;
    
    OSStatus readStatus = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);

    if (readStatus == errSecInteractionNotAllowed)
    {
        MSID_LOG_ERROR(nil, @"Encountered an error when reading teamIDHint in keychain. Keychain status %ld", (long)readStatus);

        OSStatus deleteStatus = SecItemDelete((__bridge CFDictionaryRef)query);

        if (deleteStatus != errSecSuccess)
        {
            MSID_LOG_ERROR(nil, @"Failed to delete teamID, result %d", (int)deleteStatus);

            ADALAuthenticationError* adError = [ADALAuthenticationError keychainErrorFromOperation:@"team ID deletion" status:deleteStatus correlationId:nil];
            if (error)
            {
                *error = adError;
            }
            return nil;
        }
    }

    OSStatus status = readStatus;
    
    if (readStatus == errSecItemNotFound
        || readStatus == errSecInteractionNotAllowed)
    {
        NSMutableDictionary* addQuery = [query mutableCopy];
        [addQuery setObject:(id)kSecAttrAccessibleAlways forKey:(id)kSecAttrAccessible];
        status = SecItemAdd((__bridge CFDictionaryRef)addQuery, (CFTypeRef *)&result);
    }
    
    if (status != errSecSuccess)
    {
        MSID_LOG_ERROR(nil, @"Encountered an error when reading teamIDHint in keychain. Keychain status %ld, read status %ld", (long)status, (long)readStatus);

        ADALAuthenticationError* adError = [ADALAuthenticationError keychainErrorFromOperation:@"team ID" status:status correlationId:nil];
        if (error)
        {
            *error = adError;
        }
        return nil;
    }
    
    NSString *accessGroup = [(__bridge NSDictionary *)result objectForKey:(__bridge id)(kSecAttrAccessGroup)];
    NSArray *components = [accessGroup componentsSeparatedByString:@"."];
    NSString *bundleSeedID = [components firstObject];
    
    CFRelease(result);
    
    return [bundleSeedID length] ? bundleSeedID : nil;
}

@end
