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

#import <XCTest/XCTest.h>
#import "ADBrokerHelpers.h"
#import "../ADAuthenticationBroker/ADBrokerBase64Additions.h"
#import "../ADAuthenticationBroker/NSString+ADBrokerHelperMethods.h"

@interface ADBrokerHelpersTests : XCTestCase

@end

@implementation ADBrokerHelpersTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testKDF {

    NSString* kdf = [ADBrokerHelpers computeKDFInCounterMode:[@"X1oaW28F4WyVEj9H5Yq7Z54JBv8K9746" dataUsingEncoding:NSUTF8StringEncoding]
                                                     context:[@"ALICE123E1" dataUsingEncoding:NSUTF8StringEncoding]
                                                       label:@"ALICE123"];
    XCTAssertNotNil(kdf);
}


- (void)testKDFOfEvo {
    NSString* keyEncoded = @"8jvPwsy86vlWPq6S6/LsFP6idTXYUBS6JvuLe+6eTsc=";
    NSString* derivedKeyEncoded = @"VywMlfWil62OEFBgzBQW8jeFJ4jPQE0AoAFouBYW5t0=";
    NSString* ctxEncoded = @"jNKQ3AeSGL1aBzcfeckMxEZFm4x1o1G2";
    
    NSData* key = [NSData dataWithBase64String:keyEncoded];
    NSData* ctx = [NSData dataWithBase64String:ctxEncoded];
    NSString* kdf = [ADBrokerHelpers computeKDFInCounterMode:key
                                                     context:ctx
                                                       label:@"AzureAD-SecureConversation"];
    XCTAssertTrue([NSString adSame:derivedKeyEncoded toString:kdf]);
}

@end
