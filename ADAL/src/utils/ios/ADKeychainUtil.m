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

#import "ADKeychainUtil.h"

@implementation ADKeychainUtil

+ (NSString*)keychainTeamId:(ADAuthenticationError* __autoreleasing *)error
{
    static dispatch_once_t s_once;
    static NSString* s_keychainTeamId = nil;
    
    static ADAuthenticationError* adError = nil;
    
    dispatch_once(&s_once, ^{
        ADAuthenticationError* localError = nil;
        s_keychainTeamId = [self retrieveTeamIDFromKeychain:&localError];
        adError = localError;
        SAFE_ARC_RETAIN(s_keychainTeamId);
        AD_LOG_INFO(([NSString stringWithFormat:@"Using \"%@\" Team ID for Keychain.", s_keychainTeamId]), nil, nil);
    });
    
    if (!s_keychainTeamId && error)
    {
        *error = adError;
    }
    
    return s_keychainTeamId;
}

+ (NSString*)retrieveTeamIDFromKeychain:(ADAuthenticationError * __autoreleasing *)error
{
    NSDictionary *query = @{ (id)kSecClass : (id)kSecClassGenericPassword,
                             (id)kSecAttrAccount : @"teamIDHint",
                             (id)kSecAttrService : @"",
                             (id)kSecReturnAttributes : @YES };
    CFDictionaryRef result = nil;
    
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);
    
    if (status == errSecItemNotFound)
    {
        NSMutableDictionary* addQuery = [query mutableCopy];
        [addQuery setObject:(id)kSecAttrAccessibleAlways forKey:(id)kSecAttrAccessible];
        status = SecItemAdd((__bridge CFDictionaryRef)addQuery, (CFTypeRef *)&result);
    }
    
    if (status != errSecSuccess)
    {
        ADAuthenticationError* adError = [ADAuthenticationError keychainErrorFromOperation:@"team ID" status:status correlationId:nil];
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
