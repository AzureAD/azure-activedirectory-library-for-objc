//
//  ADTelemetryUIEventTests.m
//  ADAL
//
//  Created by Sergey Demchenko on 11/6/17.
//  Copyright © 2017 MS Open Tech. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "ADTelemetryUIEvent.h"
#import "XCTestCase+TestHelperMethods.h"
#import "ADTelemetryEventStrings.h"

@interface ADTelemetryUIEventTests : XCTestCase

@end

@implementation ADTelemetryUIEventTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

- (void)testSetLoginHint_whenLogingHintNotNil_shouldHashLoginHint
{
    ADTelemetryUIEvent *event = [[ADTelemetryUIEvent alloc] initWithName:@"testEvent"
                                                                requestId:@"requestId"
                                                            correlationId:[NSUUID UUID]];
    
    [event setLoginHint:@"eric_cartman@contoso.com"];
    
    ADAssertStringEquals([event getProperties][AD_TELEMETRY_KEY_LOGIN_HINT], [@"eric_cartman@contoso.com" adComputeSHA256]);
}

@end
