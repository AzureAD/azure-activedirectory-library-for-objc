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

#import "ADKeychainQuery.h"
#import "ADProfileInfo.h"

@implementation ADKeychainQuery

- (id)init
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _cfmdKeychainQuery = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(_cfmdKeychainQuery, kSecClass, kSecClassGenericPassword);
    CFDictionaryAddValue(_cfmdKeychainQuery, kSecAttrAccessible, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly);
    
    return self;
}

- (void)dealloc
{
    CFRelease(_cfmdKeychainQuery);
}

- (void)setMatchAll
{
    CFDictionaryAddValue(_cfmdKeychainQuery, kSecMatchLimit, kSecMatchLimitAll);
}

- (void)setServiceKey:(NSString*)serviceKey
{
    CFDictionaryAddValue(_cfmdKeychainQuery, kSecAttrService, (__bridge const void *)(serviceKey));
}

- (void)setAccessGroup:(NSString*)accessGroup
{
#if !TARGET_IPHONE_SIMULATOR
    if (!accessGroup)
    {
        return;
    }
    
    CFDictionaryAddValue(_cfmdKeychainQuery, kSecAttrAccessGroup, (__bridge const void *)(accessGroup));
#else
#pragma unused (accessGroup)
#endif
}

- (void)setCopyAttributes
{
    CFDictionaryAddValue(_cfmdKeychainQuery, kSecReturnAttributes, kCFBooleanTrue);
}

- (void)setUserId:(NSString *)userId
{
    if (!userId)
    {
        return;
    }
    userId = [ADProfileInfo normalizeUserId:userId];
    CFDictionaryAddValue(_cfmdKeychainQuery, kSecAttrAccount, (__bridge const void *)(userId));
}

- (void)setGenericPasswordDictionary:(CFDictionaryRef)dictionary
{
    CFDataRef data = CFPropertyListCreateData(NULL, dictionary, kCFPropertyListBinaryFormat_v1_0, 0, NULL);
    if (!data)
    {
        return;
    }
    
    CFDictionaryAddValue(_cfmdKeychainQuery, kSecAttrGeneric, data);
    CFRelease(data);
}

- (void)setGenericPasswordData:(CFDataRef)data
{
    CFDictionaryAddValue(_cfmdKeychainQuery, kSecAttrGeneric, data);
}

- (CFDictionaryRef)queryDictionary
{
    return (CFDictionaryRef)_cfmdKeychainQuery;
}

@end
