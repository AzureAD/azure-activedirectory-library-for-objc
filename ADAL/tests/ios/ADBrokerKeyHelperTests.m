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

@interface ADBrokerKeyHelperTests : XCTestCase

@end

@implementation ADBrokerKeyHelperTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testv1Decrypt
{
    NSString* base64Key = @"BU+bLN3zTfHmyhJ325A8dJJ1tzrnKMHEfsTlStdMo0U=";
    NSData* key = [[NSData alloc] initWithBase64EncodedString:base64Key options:0];
    ADBrokerKeyHelper* keyHelper = [[ADBrokerKeyHelper alloc] init];
    ADAuthenticationError* error = nil;
     
    [keyHelper createBrokerKeyWithBytes:key error:&error];
    XCTAssertNil(error);
    
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
    NSString* base64Key = @"BU+bLN3zTfHmyhJ325A8dJJ1tzrnKMHEfsTlStdMo0U=";
    NSData* key = [[NSData alloc] initWithBase64EncodedString:base64Key options:0];
    ADBrokerKeyHelper* keyHelper = [[ADBrokerKeyHelper alloc] init];
    ADAuthenticationError* error = nil;
    
    [keyHelper createBrokerKeyWithBytes:key error:&error];
    XCTAssertNil(error);
    
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
