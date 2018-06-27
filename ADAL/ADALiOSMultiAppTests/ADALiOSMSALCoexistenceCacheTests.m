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

#import "ADALBaseUITest.h"

@interface ADALiOSMSALCoexistenceCacheTests : ADALBaseUITest

@end

@implementation ADALiOSMSALCoexistenceCacheTests

static BOOL msalAppInstalled = NO;

- (void)setUp
{
    [super setUp];

    // We only need to install app once for all the tests
    // It would be better to use +(void)setUp here, but XCUIApplication launch doesn't work then, so using this mechanism instead
    if (!msalAppInstalled)
    {
        msalAppInstalled = YES;
        [self installAppWithId:@"msal"];
    }
}

- (void)testCoexistenceWithMSAL_whenSigninInADALFirst_andSameClientId
{

}

- (void)testCoexistenceWithMSAL_whenSigninInMSALFirstAndUseScopes_andSameClientId
{

}

- (void)testCoexistenceWithMSAL_whenSigninInMSALFirstAndUseDefaultScope_andSameClientId
{

}

- (void)testCoexistenceWithMSAL_whenSigninInADALFirst_andDifferentClient_withFociSupport
{

}

- (void)testCoexistenceWithMSAL_whenSigninInMSALFirst_andDifferentClient_withFociSupport
{

}

- (void)testCoexistenceWithMSAL_whenSigninInMSALFirst_andSameClientId_andNoUserIdentifierProvided
{

}

- (void)testCoexistenceWithMSAL_whenSigninInMSALFirst_andDifferentClient_withFociSupport_andAuthorityMigration
{

}

@end
