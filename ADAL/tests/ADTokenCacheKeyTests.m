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
#import "ADTokenCacheKey.h"
#import "XCTestCase+TestHelperMethods.h"

@interface ADTokenCacheKeyTests : XCTestCase
{
    NSString* mAuthority;
    NSString* mResource;
    NSString* mClientId;
}

@end

@implementation ADTokenCacheKeyTests

- (void)setUp
{
    [super setUp];
    [self adTestBegin:ADAL_LOG_LEVEL_INFO];
    mAuthority = @"https://login.windows.net/common";;
    mResource = @"http://mywebApi.com";
    mClientId = @"myclientid";
}

- (void)tearDown
{
    [self adTestEnd];
    [super tearDown];
}

- (void)testCreate
{
    ADAuthenticationError* error = nil;
    ADTokenCacheKey* key = [ADTokenCacheKey keyWithAuthority:mAuthority resource:mResource clientId:mClientId error:&error];
    ADAssertNoError;
    XCTAssertNotNil(key);
    
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    //Bad authority:
    error = nil;
    ADTokenCacheKey* badKey = [ADTokenCacheKey keyWithAuthority:nil resource:mResource clientId:mClientId error:&error];
    [self adValidateFactoryForInvalidArgument:@"authority"
                             returnedObject:badKey
                                      error:error];
    error = nil;
    badKey = [ADTokenCacheKey keyWithAuthority:@"   " resource:mResource clientId:mClientId error:&error];
    [self adValidateFactoryForInvalidArgument:@"authority"
                             returnedObject:badKey
                                      error:error];

    //Bad clientId
    error = nil;
    badKey = [ADTokenCacheKey keyWithAuthority:mAuthority resource:mResource clientId:nil error:&error];
    [self adValidateFactoryForInvalidArgument:@"clientId"
                             returnedObject:badKey
                                      error:error];
    error = nil;
    badKey = [ADTokenCacheKey keyWithAuthority:mAuthority resource:mResource clientId:@"    " error:&error];
    [self adValidateFactoryForInvalidArgument:@"clientId"
                             returnedObject:badKey
                                      error:error];
    
    error = nil;
    ADTokenCacheKey* normal = [ADTokenCacheKey keyWithAuthority:mAuthority resource:mResource clientId:mClientId error:&error];
    ADAssertNoError;
    XCTAssertNotNil(normal);
    
    error = nil;
    ADTokenCacheKey* broad = [ADTokenCacheKey keyWithAuthority:mAuthority resource:nil clientId:mClientId error:&error];
    ADAssertNoError;
    XCTAssertNotNil(broad);
}

-(void) assertKey: (ADTokenCacheKey*) key1
         equalsTo: (ADTokenCacheKey*) key2
{
    XCTAssertTrue([key1 isEqual:key2]);
    XCTAssertTrue([key2 isEqual:key1]);
    XCTAssertEqual(key1.hash, key2.hash);
}

-(void) assertKey: (ADTokenCacheKey*) key1
      notEqualsTo: (ADTokenCacheKey*) key2
{
    XCTAssertFalse([key1 isEqual:key2]);
    XCTAssertFalse([key2 isEqual:key1]);
    XCTAssertNotEqual(key1.hash, key2.hash);
}

- (void)testCompare
{
    ADAuthenticationError* error = nil;
    ADTokenCacheKey* normal = [ADTokenCacheKey keyWithAuthority:mAuthority resource:mResource clientId:mClientId error:&error];
    ADAssertNoError;
    XCTAssertNotNil(normal);
    [self assertKey:normal equalsTo:normal];//Self
    [self assertKey:normal notEqualsTo:nil];
    
    {
        error = nil;
        ADTokenCacheKey* same = [ADTokenCacheKey keyWithAuthority:mAuthority resource:mResource clientId:mClientId error:&error];
        ADAssertNoError;
        XCTAssertNotNil(same);
        [self assertKey:normal equalsTo:normal];
    }
    
    {
        error = nil;
        ADTokenCacheKey* differentAuth = [ADTokenCacheKey keyWithAuthority:@"https://login.windows.com/common" resource:mResource clientId:mClientId error:&error];
        ADAssertNoError;
        XCTAssertNotNil(differentAuth);
        [self assertKey:normal notEqualsTo:differentAuth];
    }
    
    {
        error = nil;
        ADTokenCacheKey* differentRes = [ADTokenCacheKey keyWithAuthority:mAuthority resource:@"another resource" clientId:mClientId error:&error];
        ADAssertNoError;
        XCTAssertNotNil(differentRes);
        [self assertKey:normal notEqualsTo:differentRes];
    }
    
    {
        error = nil;
        ADTokenCacheKey* differentClient = [ADTokenCacheKey keyWithAuthority:mAuthority resource:mResource clientId:@"another clientid" error:&error];
        ADAssertNoError;
        XCTAssertNotNil(differentClient);
        [self assertKey:normal notEqualsTo:differentClient];
    }
    
    error = nil;
    ADTokenCacheKey* broad = [ADTokenCacheKey keyWithAuthority:mAuthority resource:nil clientId:mClientId error:&error];
    ADAssertNoError;
    XCTAssertNotNil(broad);
    [self assertKey:broad equalsTo:broad];
    [self assertKey:broad notEqualsTo:normal];
    
    {
        error = nil;
        ADTokenCacheKey* sameBroad = [ADTokenCacheKey keyWithAuthority:mAuthority resource:nil clientId:mClientId error:&error];
        ADAssertNoError;
        XCTAssertNotNil(sameBroad);
        [self assertKey:broad equalsTo:sameBroad];
    }

    {
        error = nil;
        ADTokenCacheKey* differentAuthBroad = [ADTokenCacheKey keyWithAuthority:@"https://login.windows.com/common" resource:nil clientId:mClientId error:&error];
        ADAssertNoError;
        XCTAssertNotNil(differentAuthBroad);
        [self assertKey:broad notEqualsTo:differentAuthBroad];
    }
    
    {
        error = nil;
        ADTokenCacheKey* differentClientBroad = [ADTokenCacheKey keyWithAuthority:mAuthority resource:nil clientId:@"another authority" error:&error];
        ADAssertNoError;
        XCTAssertNotNil(differentClientBroad);
        [self assertKey:broad notEqualsTo:differentClientBroad];
    }
}


@end
