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

#import <Foundation/Foundation.h>
#import "ADAuthenticationError.h"

#define kChosenCipherKeySize    kCCKeySizeAES256
#define kSymmetricKeyTag        "com.microsoft.adBrokerKey"

@interface ADBrokerKeyHelper : NSObject
{
    NSData * _symmetricTag;
    NSData * _symmetricKey;
}

- (id)init;

- (BOOL)createBrokerKey:(NSError * __autoreleasing*)error;
- (BOOL)deleteSymmetricKey: (NSError * __autoreleasing*) error;
- (NSData*)getBrokerKey:(NSError * __autoreleasing*)error;
- (NSData*)decryptBrokerResponse:(NSData*)response
                         version:(NSInteger)version
                           error:(NSError * __autoreleasing*)error;
- (NSData*)decryptBrokerResponse:(NSData *)response
                             key:(const void*)key
                            size:(size_t)size
                           error:(NSError *__autoreleasing *)error;

+ (NSDictionary *)decryptBrokerResponse:(NSDictionary *)response
                           correlationId:(NSUUID *)correlationId
                                   error:(NSError * __autoreleasing *)error;

// NOTE: Used for testing purposes only. Does not change keychain entries.
+ (void)setSymmetricKey:(NSString *)base64Key;
+ (NSData *)symmetricKey;

@end
