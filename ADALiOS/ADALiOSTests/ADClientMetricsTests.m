//
//  ADClientMetricsTests.m
//  ADALiOS
//
//  Created by Kanishk Panwar on 11/8/14.
//  Copyright (c) 2014 MS Open Tech. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "../ADALiOS/ADClientMetrics.h"

@interface ADClientMetricsTests : XCTestCase

@end

@implementation ADClientMetricsTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testMetrics {

    ADClientMetrics* metrics = [ADClientMetrics getInstance];
    NSMutableDictionary* header = [NSMutableDictionary new];
    [metrics beginClientMetricsRecordForEndpoint:@"https://login.windows.net/common/oauth2/token" correlationId:@"correlationId" requestHeader:header];
    [metrics endClientMetricsRecord:@"error"];
    XCTAssertEqual([header count], 0);
    [metrics beginClientMetricsRecordForEndpoint:@"https://login.windows.net/common/oauth2/token" correlationId:@"correlationId" requestHeader:header];
    XCTAssertEqual([header count], 4);
}

@end
