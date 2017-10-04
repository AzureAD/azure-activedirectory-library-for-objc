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

#import <UIKit/UIKit.h>
#import <XCTest/XCTest.h>
#import "ADBrokerKeyHelper.h"

#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonDigest.h>
#import <Security/Security.h>

enum {
    CSSM_ALGID_NONE =                   0x00000000L,
    CSSM_ALGID_VENDOR_DEFINED =         CSSM_ALGID_NONE + 0x80000000L,
    CSSM_ALGID_AES
};

@interface ADBrokerKeyHelperTests : ADTestCase

@end

@implementation ADBrokerKeyHelperTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [ADBrokerKeyHelper setSymmetricKey:nil];
    [super tearDown];
}

- (void)testv1Decrypt
{
    [ADBrokerKeyHelper setSymmetricKey:@"BU-bLN3zTfHmyhJ325A8dJJ1tzrnKMHEfsTlStdMo0U"];
    ADBrokerKeyHelper* keyHelper = [[ADBrokerKeyHelper alloc] init];
    ADAuthenticationError* error = nil;
    
    NSString* v1EncryptedPayload = @"OxDgUethOjve95lfr1OIFjv9ExbhxTTESae11KZChY2SAsDBZCyRI87/HCutimLfIpvqWHJ7P6ygVGJlnr1yHZf4aguJ4zq1auczsXeTPPYoNVxHNGbbMJgAkjcnCI6SJG9JqXlS8IjVNFDTZvVswlLWzwsQLL5O36/gGM77eONyhMkRexN36wMMgSkrtTzov1OOn2od9ErutVTyBNZ+bNbAhzYQgNzkvbgERFdBMlDN7EIuFO4TMgizcYhbvaGY+jNb8Ktwbk0hXxKfMKm8HL332ub3RbRrW0BWPJACPtyzN3X9pnxncZHg8hZJzYh3";
    
    NSData* decrypted = [keyHelper decryptBrokerResponse:[[NSData alloc] initWithBase64EncodedString:v1EncryptedPayload options:0]
                                                 version:1
                                                   error:&error];
    XCTAssertNil(error);
    XCTAssertNotNil(decrypted);
    
    NSString* payload = @"VGhpcyBpcyB0aGUgc29uZyB0aGF0IGRvZXNuJ3QgZW5kLCB5ZXMgaXQgZ29lcyBvbiBhbmQgb24gbXkgZnJpZW5kLiBTb21lIHBlb3BsZSBzdGFydGVkIHNpbmdpbmcgaXQgbm90IGtub3dpbmcgd2hhdCBpdCB3YXMsIGFuZCB0aGV5J2xsIGNvbnRpbnVlIHNpbmdpbmcgaXQgZm9yZXZlciBqdXN0IGJlY2F1c2UuLi4";
    XCTAssertEqualObjects(decrypted, [payload dataUsingEncoding:NSUTF8StringEncoding]);
}

- (void)testv2Decrypt
{
    [ADBrokerKeyHelper setSymmetricKey:@"BU-bLN3zTfHmyhJ325A8dJJ1tzrnKMHEfsTlStdMo0U"];
    ADBrokerKeyHelper* keyHelper = [[ADBrokerKeyHelper alloc] init];
    ADAuthenticationError* error = nil;
    
    NSString* v2EncryptedPayload = @"OwkUbeZ63OlLI1xsNUXOJKmJgjhApcV6bEzFI6cdtE4UtsboGnJLjUtJRySO8ol97W431BdpwnuFD8tImkjUx++oNAMU483Q1xpuc5mCNVZcpDpnMoW2EC9oM5slGTPvvmDBxu3MHbLVVKWB616eKUdSKGOBnBUWDZp6QJJXpwEzwZuoycmmbQBF2SI1Ur5bluma8d23hANpV1c0qCGtPvEcLXWp7vNp5gkIsd6rGAkuuk31GJ3E8j+gfd8XymUEFc8g9ikx4JG0JnRwmRkzgVVKgszDPlPJrqlGlCZqa0SiF8V0pT3CqM6HURkqmCvK";
    
    NSData* decrypted = [keyHelper decryptBrokerResponse:[[NSData alloc] initWithBase64EncodedString:v2EncryptedPayload options:0]
                                                 version:2
                                                   error:&error];
    XCTAssertNil(error);
    XCTAssertNotNil(decrypted);
    
    NSString* payload = @"VGhpcyBpcyB0aGUgc29uZyB0aGF0IGRvZXNuJ3QgZW5kLCB5ZXMgaXQgZ29lcyBvbiBhbmQgb24gbXkgZnJpZW5kLiBTb21lIHBlb3BsZSBzdGFydGVkIHNpbmdpbmcgaXQgbm90IGtub3dpbmcgd2hhdCBpdCB3YXMsIGFuZCB0aGV5J2xsIGNvbnRpbnVlIHNpbmdpbmcgaXQgZm9yZXZlciBqdXN0IGJlY2F1c2UuLi4";
    XCTAssertEqualObjects(decrypted, [payload dataUsingEncoding:NSUTF8StringEncoding]);
}

@end
