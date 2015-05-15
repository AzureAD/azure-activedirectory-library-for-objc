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
#import "ADBrokerJWEResponse.h"

@interface ADBrokerJWEResponseTests : XCTestCase

@end

@implementation ADBrokerJWEResponseTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testInit {
    NSString* rawJwe = @"eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAifQ.AIMpIcH77YJ_c5hSUxtR-Ja0bSawRHMaoT_hkNBD87vgI2IVjRaJoHDv8NXz72Ryjh1Wrk6jEIUeB197srVMgVw1IiVWL16KORZUfb4tX3ho4W9KN0y8AO9wVfmJuzR-eWsaqHKrW7SQo68nguxZ-HrXwAOCOGK3Abm47rXKsjBjgNa9zeLCpowMVI7ZKAJzxjPGuJ_eqClFTCCfC3BMUOH0TzHc4vFGQyMnOqfHIg1dd48jFZ6ObBNsu1tikaKIYA8M47dYEK9f5NtRTAKUxhoifROK2rdTTODJwTfjZqH_WEbCcL14CpaIgxouYJiFxaSVy0qIxICxOZDXzDRTodQ.9pLxwR4TjvMrPN6l.JQ.X-7yuKygZuh53C2MYTP8xg";
    ADBrokerJWEResponse* response = [[ADBrokerJWEResponse alloc] initWithRawJWE:rawJwe];
    XCTAssertNotNil(response);
}

@end
