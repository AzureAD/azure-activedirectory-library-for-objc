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
#import "ADBrokerContext.h"
#import "NSString+ADHelperMethods.h"
#import "NSDictionary+ADExtensions.h"

@interface ADBrokerContextTest : XCTestCase

@end

@interface ADBrokerContext()

+ (NSString*)filteredQPString:(NSDictionary*)queryParams;

@end

@implementation ADBrokerContextTest

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testQPFilter
{
    NSString* filteredQP = nil;
    
    NSString* allAllowedQP = @"mamver=2&msafed=0";
    filteredQP = [ADBrokerContext filteredQPString:[NSDictionary adURLFormDecode:allAllowedQP]];
    XCTAssertEqualObjects(allAllowedQP, filteredQP);
    
    NSString* allDisallowedQP = @"sajkdfhasoikjsaaklsdasklda=njkanlsdfawkdjla&asjkdbnakljsdnlaksda=asjdnaskjldnasd";
    filteredQP = [ADBrokerContext filteredQPString:[NSDictionary adURLFormDecode:allDisallowedQP]];
    XCTAssertTrue([NSString adIsStringNilOrBlank:filteredQP]);
    
    NSString* mixedQP = @"asddsfsdfdsfsd=sadfasdfasdas&msafed=0&asdkjlsjdjkl=sjkhdkas&dsffsdjkfndskjfds=sdfdsfsd";
    filteredQP = [ADBrokerContext filteredQPString:[NSDictionary adURLFormDecode:mixedQP]];
    XCTAssertEqualObjects(filteredQP, @"msafed=0");
}

@end
