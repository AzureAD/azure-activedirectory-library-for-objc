//
//  ADTelemetryAPIEventTests.m
//  ADAL
//
//  Created by Sergey Demchenko on 11/6/17.
//  Copyright © 2017 MS Open Tech. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "ADTelemetryAPIEvent.h"
#import "XCTestCase+TestHelperMethods.h"
#import "ADTelemetryEventStrings.h"

@interface ADTelemetryAPIEventTests : ADTestCase

@end

@implementation ADTelemetryAPIEventTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

- (void)testSetUserInformation_whenUserIdProvided_shouldHashUserId
{
    NSUUID *correlationId = [NSUUID UUID];
    ADTelemetryAPIEvent *event = [[ADTelemetryAPIEvent alloc] initWithName:@"testEvent1"
                                                                 requestId:@"requestId"
                                                             correlationId:correlationId];
    ADUserInformation *userInfo = [self adCreateUserInformation:@"eric_cartman@contoso.com"];
    
    [event setUserInformation:userInfo];
    
    ADAssertStringEquals([event getProperties][AD_TELEMETRY_KEY_USER_ID], [@"eric_cartman@contoso.com" adComputeSHA256]);
}

- (void)testSetUserInformation_whenTenantIdProvided_shouldHashTenantId
{
    NSUUID *correlationId = [NSUUID UUID];
    ADTelemetryAPIEvent *event = [[ADTelemetryAPIEvent alloc] initWithName:@"testEvent1"
                                                                 requestId:@"requestId"
                                                             correlationId:correlationId];
    ADUserInformation *userInfo = [self adCreateUserInformation:@"eric_cartman@contoso.com"];
    
    [event setUserInformation:userInfo];
    
    ADAssertStringEquals([event getProperties][AD_TELEMETRY_KEY_TENANT_ID], [@"6fd1f5cd-a94c-4335-889b-6c598e6d8048" adComputeSHA256]);
}

- (void)testSetUserId_whenUserIdValid_shouldHashUserId
{
    NSUUID *correlationId = [NSUUID UUID];
    ADTelemetryAPIEvent *event = [[ADTelemetryAPIEvent alloc] initWithName:@"testEvent1"
                                                                 requestId:@"requestId"
                                                             correlationId:correlationId];
    
    [event setUserId:@"eric_cartman@contoso.com"];
    
    ADAssertStringEquals([event getProperties][AD_TELEMETRY_KEY_USER_ID], [@"eric_cartman@contoso.com" adComputeSHA256]);
}

@end
