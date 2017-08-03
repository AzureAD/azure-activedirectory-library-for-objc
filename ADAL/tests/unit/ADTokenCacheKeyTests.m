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
    [super tearDown];
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
