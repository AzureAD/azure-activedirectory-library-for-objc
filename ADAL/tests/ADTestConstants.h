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

#ifndef ADTestConstants_h
#define ADTestConstants_h

#define TEST_AUTHORITY @"https://login.windows.net/contoso.com"
#define TEST_REDIRECT_URL_STRING @"urn:ietf:wg:oauth:2.0:oob"
#define TEST_REDIRECT_URL [NSURL URLWithString:TEST_REDIRECT_URL_STRING]
#define TEST_RESOURCE @"resource"
#define TEST_USER_ID @"eric_cartman@contoso.com"
#define TEST_CLIENT_ID @"c3c7f5e5-7153-44d4-90e6-329686d48d76"
#define TEST_ACCESS_TOKEN @"access token"
#define TEST_ACCESS_TOKEN_TYPE @"access token type"
#define TEST_REFRESH_TOKEN @"refresh token"
#define TEST_UPDATE_REFRESH_TOKEN @"updated refresh token"
#define TEST_CORRELATION_ID ({NSUUID *testID = [[NSUUID alloc] initWithUUIDString:@"6fd1f5cd-a94c-4335-889b-6c598e6d8048"]; testID;})


#endif /* ADTestConstants_h */
