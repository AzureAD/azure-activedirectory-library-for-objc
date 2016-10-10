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
#import "ADAuthenticationSettings.h"

@implementation ADTestAppCache
{
    NSData* _data;
}

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
        [cache readFromFile:[self defaultSavePath]];
        
        [[ADAuthenticationSettings sharedInstance] setDefaultStorageDelegate:cache];
    });
    
    return cache;
}

+ (NSString*)defaultSavePath
{
    static dispatch_once_t once;
    static NSString* path = nil;
    
    dispatch_once(&once, ^{
        NSURL* homeDir = [[NSFileManager defaultManager] homeDirectoryForCurrentUser];
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

- (void)willAccessCache:(nonnull ADTokenCache *)cache
{
    @synchronized(self)
    {
        [cache deserialize:_data error:nil];
    }
}

- (void)didAccessCache:(nonnull ADTokenCache *)cache
{
    @synchronized(self)
    {
        //[_data release];
        _data = [cache serialize];
        //[_data retain];
    }
}

- (void)willWriteCache:(nonnull ADTokenCache *)cache
{
    @synchronized(self)
    {
        [cache deserialize:_data error:nil];
    }
}

- (void)didWriteCache:(nonnull ADTokenCache *)cache
{
    @synchronized(self)
    {
        //[_data release];
        _data = [cache serialize];
        //[_data retain];
        [self writeToFile:[ADTestAppCache defaultSavePath]];
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

- (void)readFromKeychain
{
    
}

- (void)writeToKeychain
{
    @synchronized (self)
    {
        if (!_data)
        {
            return;
        }
        
        NSDictionary* writeQuery
    }
}

@end
