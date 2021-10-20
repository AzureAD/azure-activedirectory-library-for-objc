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
#import "ADALTokenCacheKey.h"
#import "XCTestCase+TestHelperMethods.h"

@interface ADALTokenCacheKeyTests : ADTestCase
{
    NSString* mAuthority;
    NSString* mResource;
    NSString* mClientId;
}

@end

@implementation ADALTokenCacheKeyTests

- (void)setUp
{
    [super setUp];
    
    mAuthority = @"https://login.windows.net/common";;
    mResource = @"http://mywebApi.com";
    mClientId = @"myclientid";
}

- (void)tearDown
{
    [super tearDown];
}

-(void) assertKey: (ADALTokenCacheKey*) key1
         equalsTo: (ADALTokenCacheKey*) key2
{
    XCTAssertTrue([key1 isEqual:key2]);
    XCTAssertTrue([key2 isEqual:key1]);
    XCTAssertEqual(key1.hash, key2.hash);
}

-(void) assertKey: (ADALTokenCacheKey*) key1
      notEqualsTo: (ADALTokenCacheKey*) key2
{
    XCTAssertFalse([key1 isEqual:key2]);
    XCTAssertFalse([key2 isEqual:key1]);
    XCTAssertNotEqual(key1.hash, key2.hash);
}

- (void)testCompare
{
    ADALAuthenticationError* error = nil;
    ADALTokenCacheKey* normal = [ADALTokenCacheKey keyWithAuthority:mAuthority resource:mResource clientId:mClientId error:&error];
    ADAssertNoError;
    XCTAssertNotNil(normal);
    [self assertKey:normal equalsTo:normal];//Self
    [self assertKey:normal notEqualsTo:nil];
    
    {
        error = nil;
        ADALTokenCacheKey* same = [ADALTokenCacheKey keyWithAuthority:mAuthority resource:mResource clientId:mClientId error:&error];
        ADAssertNoError;
        XCTAssertNotNil(same);
        [self assertKey:normal equalsTo:normal];
    }
    
    {
        error = nil;
        ADALTokenCacheKey* differentAuth = [ADALTokenCacheKey keyWithAuthority:@"https://login.windows.com/common" resource:mResource clientId:mClientId error:&error];
        ADAssertNoError;
        XCTAssertNotNil(differentAuth);
        [self assertKey:normal notEqualsTo:differentAuth];
    }
    
    {
        error = nil;
        ADALTokenCacheKey* differentRes = [ADALTokenCacheKey keyWithAuthority:mAuthority resource:@"another resource" clientId:mClientId error:&error];
        ADAssertNoError;
        XCTAssertNotNil(differentRes);
        [self assertKey:normal notEqualsTo:differentRes];
    }
    
    {
        error = nil;
        ADALTokenCacheKey* differentClient = [ADALTokenCacheKey keyWithAuthority:mAuthority resource:mResource clientId:@"another clientid" error:&error];
        ADAssertNoError;
        XCTAssertNotNil(differentClient);
        [self assertKey:normal notEqualsTo:differentClient];
    }
    
    error = nil;
    ADALTokenCacheKey* broad = [ADALTokenCacheKey keyWithAuthority:mAuthority resource:nil clientId:mClientId error:&error];
    ADAssertNoError;
    XCTAssertNotNil(broad);
    [self assertKey:broad equalsTo:broad];
    [self assertKey:broad notEqualsTo:normal];
    
    {
        error = nil;
        ADALTokenCacheKey* sameBroad = [ADALTokenCacheKey keyWithAuthority:mAuthority resource:nil clientId:mClientId error:&error];
        ADAssertNoError;
        XCTAssertNotNil(sameBroad);
        [self assertKey:broad equalsTo:sameBroad];
    }

    {
        error = nil;
        ADALTokenCacheKey* differentAuthBroad = [ADALTokenCacheKey keyWithAuthority:@"https://login.windows.com/common" resource:nil clientId:mClientId error:&error];
        ADAssertNoError;
        XCTAssertNotNil(differentAuthBroad);
        [self assertKey:broad notEqualsTo:differentAuthBroad];
    }
    
    {
        error = nil;
        ADALTokenCacheKey* differentClientBroad = [ADALTokenCacheKey keyWithAuthority:mAuthority resource:nil clientId:@"another authority" error:&error];
        ADAssertNoError;
        XCTAssertNotNil(differentClientBroad);
        [self assertKey:broad notEqualsTo:differentClientBroad];
    }
}


@end
