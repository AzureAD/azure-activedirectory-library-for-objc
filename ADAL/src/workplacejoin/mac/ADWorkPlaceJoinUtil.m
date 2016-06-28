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

#import "ADWorkPlaceJoinUtil.h"


@implementation ADWorkPlaceJoinUtil

+ (ADRegistrationInformation*)getRegistrationInformation:(NSUUID *)correlationId
                                                   error:(ADAuthenticationError * __autoreleasing *)error
{
    ADAuthenticationError* adError =
    [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_SERVER_UNSUPPORTED_REQUEST
                                           protocolCode:nil
                                           errorDetails:@"Conditional Access is not supported on macOS."
                                          correlationId:correlationId];
    
    if (error)
    {
        *error = adError;
    }
    
    return nil;
}

+ (NSString*)keychainTeamId
{
    static dispatch_once_t s_once;
    static NSString* s_keychainTeamId = nil;
    
    dispatch_once(&s_once, ^{
        s_keychainTeamId = [self retrieveTeamIDFromKeychain];
        AD_LOG_INFO(([NSString stringWithFormat:@"Using \"%@\" Team ID for Keychain.", s_keychainTeamId]), nil, nil);
    });
    
    return s_keychainTeamId;
}

+ (NSString*)retrieveTeamIDFromKeychain
{
    NSDictionary *query = [NSDictionary dictionaryWithObjectsAndKeys:
                           (__bridge id)(kSecClassGenericPassword), kSecClass,
                           @"bundleSeedID", kSecAttrAccount,
                           @"", kSecAttrService,
                           (id)kCFBooleanTrue, kSecReturnAttributes,
                           nil];
    CFDictionaryRef result = nil;
    
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);
    
    if (status == errSecItemNotFound)
    {
        status = SecItemAdd((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);
    }
    
    if (status != errSecSuccess)
    {
        return nil;
    }
    
    NSString *accessGroup = [(__bridge NSDictionary *)result objectForKey:(__bridge id)(kSecAttrAccessGroup)];
    NSArray *components = [accessGroup componentsSeparatedByString:@"."];
    NSString *bundleSeedID = [components firstObject];
    
    CFRelease(result);
    
    return [bundleSeedID length] ? bundleSeedID : nil;
}

@end

