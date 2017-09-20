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

@interface NSString (ADHelperMethods)

/*! Encodes string to the Base64 encoding. */
- (NSString *)adBase64UrlEncode;
/*! Decodes string from the Base64 encoding. */
- (NSString *)adBase64UrlDecode;

/*! Returns YES if the string is nil, or contains only white space */
+ (BOOL)adIsStringNilOrBlank:(NSString *)string;

/*! Returns the same string, but without the leading and trailing whitespace */
- (NSString *)adTrimmedString;

/*! Decodes a previously URL encoded string. */
- (NSString *)adUrlFormDecode;

/*! Encodes the string to pass it as a URL agrument. */
- (NSString *)adUrlFormEncode;

/*! Converts base64 String to NSData */
+ (NSData *)adBase64UrlDecodeData:(NSString *)encodedString;

/*! Converts NSData to base64 String */
+ (NSString *)adBase64UrlEncodeData:(NSData *)data;

- (NSString*)adComputeSHA256;

@end
