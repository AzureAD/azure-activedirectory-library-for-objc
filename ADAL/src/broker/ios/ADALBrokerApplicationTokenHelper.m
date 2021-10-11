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

#import "ADALBrokerApplicationTokenHelper.h"
#import "MSIDKeychainUtil.h"

@interface ADALBrokerApplicationTokenHelper()

@property (nonatomic) NSString *keychainAccessGroup;

@end

@implementation ADALBrokerApplicationTokenHelper

- (instancetype)initWithAccessGroup:(NSString *)accessGroup
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    if (!accessGroup)
    {
        accessGroup = [[NSBundle mainBundle] bundleIdentifier];
    }
    
    if (!MSIDKeychainUtil.teamId)
    {
        return nil;
    }
    
    // Add team prefix to keychain group if it is missed.
    if (![accessGroup hasPrefix:MSIDKeychainUtil.teamId])
    {
        accessGroup = [MSIDKeychainUtil accessGroup:accessGroup];
    }
    
    _keychainAccessGroup = accessGroup;
    
    return self;
}

- (BOOL)saveApplicationBrokerToken:(NSString *)token
                          clientId:(NSString *)clientId
{
    NSDictionary *keyQuery = [self applicationTokenQueryWithClientId:clientId];
    
    NSDictionary *updateAttributes = @{(id)kSecValueData : [token dataUsingEncoding:NSUTF8StringEncoding]};
    
    OSStatus err = SecItemUpdate((CFDictionaryRef)keyQuery, (CFDictionaryRef)updateAttributes);
    
    MSID_LOG_INFO(nil, @"Updating application token for clientId %@", clientId);
    
    if (err == errSecItemNotFound)
    {
        MSID_LOG_INFO(nil, @"Application token not found. Saving new one in cache");
        
        NSMutableDictionary *mutableKeyQuery = [keyQuery mutableCopy];
        mutableKeyQuery[(id)kSecAttrAccessible] = (id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
        mutableKeyQuery[(id)kSecAttrAccessGroup] = self.keychainAccessGroup;
        mutableKeyQuery[(id)kSecValueData] = [token dataUsingEncoding:NSUTF8StringEncoding];
        
        err = SecItemAdd((CFDictionaryRef)mutableKeyQuery, NULL);
    }
    
    if (err != errSecSuccess)
    {
        MSID_LOG_ERROR(nil, @"Failed to write application token. Application will not have SSO in broker for the next request, write error %ld", (long)err);
        return NO;
    }
    
    return YES;
}

- (NSString *)getApplicationBrokerTokenForClientId:(NSString *)clientId
{
    OSStatus err = noErr;
    NSMutableDictionary *keyQuery = [[self applicationTokenQueryWithClientId:clientId] mutableCopy];
    keyQuery[(id)kSecReturnData] = @YES;
    
    // Get the key bits.
    CFDataRef key = nil;
    err = SecItemCopyMatching((__bridge CFDictionaryRef)keyQuery, (CFTypeRef *)&key);
    if (err == errSecSuccess)
    {
        MSID_LOG_INFO(nil, @"Found a valid application token");
        NSData *result = (__bridge_transfer NSData*)key;
        return [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
    }
    
    MSID_LOG_INFO(nil, @"Didn't find any valid application tokens with result %ld", (long)err);
    
    return nil;
}

- (NSDictionary *)applicationTokenQueryWithClientId:(NSString *)clientId
{
    return @{
             (id)kSecClass : (id)kSecClassKey,
             (id)kSecAttrApplicationTag : [self applicationTokenTagWithClientId:clientId],
             (id)kSecAttrAccessGroup : self.keychainAccessGroup
             };
}

- (NSData *)applicationTokenTagWithClientId:(NSString *)clientId
{
    return [[NSString stringWithFormat:@"com.microsoft.adBrokerAppToken-%@", clientId] dataUsingEncoding:NSUTF8StringEncoding];
}

@end
