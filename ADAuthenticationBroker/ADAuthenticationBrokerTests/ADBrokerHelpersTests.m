//
//  ADBrokerHelpersTests.m
//  ADAuthenticationBroker
//
//  Created by Kanishk Panwar on 2/15/15.
//  Copyright (c) 2015 Microsoft Corp. All rights reserved.
//


#import <XCTest/XCTest.h>
#import "ADBrokerHelpers.h"

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
                                                     context:@"ALICE123E1"
                                                       label:@"ALICE123"];
    XCTAssertNotNil(kdf);
}

@end
