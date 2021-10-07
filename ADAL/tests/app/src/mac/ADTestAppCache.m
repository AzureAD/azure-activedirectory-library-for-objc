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

#import "ADTestAppCache.h"
#import "ADALAuthenticationSettings.h"
#import "ADAL_Internal.h"

#define DEFAULT_KEYCHAIN_ATTRS \
    (id)kSecClass : (id)kSecClassGenericPassword, \
    (id)kSecAttrAccount : @"AdalTestApp", \
    (id)kSecAttrService : @"ADALCache" \

@implementation ADTestAppCache

+ (void)load
{
    [self sharedCache];
}

+ (ADTestAppCache*)sharedCache
{
    static dispatch_once_t once;
    static ADTestAppCache* cache = nil;
    
    dispatch_once(&once, ^{
        cache = [[ADTestAppCache alloc] init];
#ifdef FILE_BASED_TEST_CACHE
        [cache readFromFile:[self defaultSavePath]];
#else
        [cache readFromKeychain];
#endif
        [[ADALAuthenticationSettings sharedInstance] setDefaultStorageDelegate:cache];
    });
    
    return cache;
}

+ (NSString*)defaultSavePath
{
    static dispatch_once_t once;
    static NSString* path = nil;
    
    dispatch_once(&once, ^{
        NSURL* homeDir = [NSURL fileURLWithPath:NSHomeDirectory()];
        path = [homeDir URLByAppendingPathComponent:@"TestApp.adalcache"].path;
    });
    
    return path;
}

- (id)copyWithZone:(NSZone*)zone
{
    ADTestAppCache* cache = [[self.class allocWithZone:zone] init];
    cache->_data = [_data copyWithZone:zone];
    return cache;
}

- (void)willAccessCache:(nonnull ADALTokenCache *)cache
{
    @synchronized(self)
    {
#ifdef FILE_BASED_TEST_CACHE
        [self readFromFile:[[self class] defaultSavePath]];
#else
        [self readFromKeychain];
#endif
        
        if (_data)
        {
            [cache deserialize:_data error:nil];
        }
    }
}

- (void)didAccessCache:(nonnull ADALTokenCache *)cache
{
    // Nothing changed in the cache so no need to do anything. If you're implementing
    // this with proper locking this is where you would let go of the lock.
    (void)cache;
}

- (void)willWriteCache:(nonnull ADALTokenCache *)cache
{
    @synchronized(self)
    {
#ifdef FILE_BASED_TEST_CACHE
        [self readFromFile:[[self class] defaultSavePath]];
#else
        [self readFromKeychain];
#endif
        [cache deserialize:_data error:nil];
    }
}

- (void)didWriteCache:(nonnull ADALTokenCache *)cache
{
    @synchronized(self)
    {
        _data = [cache serialize];
#ifdef FILE_BASED_TEST_CACHE
        [self writeToFile:[ADTestAppCache defaultSavePath]];
#else
        [self writeToKeychain];
#endif
    }
}

- (void)readFromFile:(NSString *)filePath
{
    @synchronized (self)
    {
        _data = [NSData dataWithContentsOfFile:filePath];
    }
}

- (void)writeToFile:(NSString *)filePath
{
    @synchronized (self)
    {
        // NOTE: This "implementation" does not provide any extra data security
        // and is not recommended for production apps.
        if (![_data writeToFile:filePath atomically:YES])
        {
            NSLog(@"Failed to write cache to %@!", filePath);
        }
    }
}

- (OSStatus)readFromKeychain
{
    @synchronized (self)
    {
        NSDictionary* readQuery =
        @{
          DEFAULT_KEYCHAIN_ATTRS,
          (id)kSecReturnData : @YES
          };
        
        CFDataRef data = NULL;
        OSStatus status = SecItemCopyMatching((CFDictionaryRef)readQuery, (CFTypeRef *)&data);
        
        _data = (__bridge_transfer NSData*)data;
        
        return status;
    }
}

- (OSStatus)writeToKeychain
{
    @synchronized (self)
    {
        if (!_data)
        {
            return errSecItemNotFound;
        }
        
        NSDictionary* updateQuery =
        @{
          DEFAULT_KEYCHAIN_ATTRS
          };
        
        NSDictionary* attrToUpdate =
        @{
          (id)kSecValueData : _data
          };
        
        OSStatus status = SecItemUpdate((CFDictionaryRef)updateQuery, (CFDictionaryRef)attrToUpdate);
        if (status == errSecItemNotFound)
        {
            NSDictionary* writeQuery =
            @{
                DEFAULT_KEYCHAIN_ATTRS,
                (id)kSecValueData : _data,
            };
            status = SecItemAdd((CFDictionaryRef)writeQuery, NULL);
        }
        return status;
    }
}

- (BOOL)clearCacheWithError:(NSError *__autoreleasing *)error
{
    @synchronized (self)
    {
        if (![[ADALTokenCache defaultCache] deserialize:nil error:nil])
        {
            return NO;
        }

#ifdef FILE_BASED_TEST_CACHE
        return [[NSFileManager defaultManager] removeItemAtPath:[ADTestAppCache defaultSavePath] error:error];
#else
        OSStatus deleteResult = SecItemDelete((CFDictionaryRef)@{ DEFAULT_KEYCHAIN_ATTRS });

        if (deleteResult == errSecSuccess || deleteResult == errSecItemNotFound)
        {
            return YES;
        }
        else if (error)
        {
            *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:deleteResult userInfo:nil];
        }

        return NO;
#endif
    }
}

@end
