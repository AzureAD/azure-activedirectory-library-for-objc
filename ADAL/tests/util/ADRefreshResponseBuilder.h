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

#import <Foundation/Foundation.h>

@interface ADRefreshResponseBuilder : NSObject

@property (copy, readwrite, nonnull) NSString *authority;
@property (copy, readwrite, nonnull) NSString *clientId;
@property (copy, readwrite, nonnull) NSString *resource;
@property (copy, readwrite, nonnull) NSUUID *correlationId;

@property (copy, readwrite, nonnull) NSString *oldRefreshToken;

@property (readonly, nonnull) NSMutableDictionary *requestHeaders;
@property (readonly, nonnull) NSMutableDictionary *requestBody;

@property (readwrite) NSInteger responseCode;
@property (readonly, nonnull) NSMutableDictionary *responseHeaders;
@property (readonly, nonnull) NSMutableDictionary *responseBody;

@property (copy, readwrite, nonnull) NSString *updatedRefreshToken;
@property (copy, readwrite, nonnull) NSString *updatedAccessToken;
@property (copy, readwrite, nonnull) NSDate *expirationTime;
@property (copy, readwrite, nullable) NSString *updatedIdToken;

- (nonnull ADTestURLResponse *)response;

@end
