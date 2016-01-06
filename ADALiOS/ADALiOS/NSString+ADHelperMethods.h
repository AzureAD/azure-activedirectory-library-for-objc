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

#import <Foundation/Foundation.h>

@interface NSString (ADHelperMethods)

/*! Encodes string to the Base64 encoding. */
- (NSString *)adBase64UrlEncode;
/*! Decodes string from the Base64 encoding. */
- (NSString *)adBase64UrlDecode;

/*! Returns YES if the string is nil, or contains only white space */
+ (BOOL) adIsStringNilOrBlank: (NSString*)string;

/*! Returns YES if the passed string is contained. Throws if the passed
 argument is nil or empty string.
 @param cotnained:The string to search
 */
- (BOOL) adContainsString: (NSString*) contained;

/*! Returns the same string, but without the leading and trailing whitespace */
- (NSString*)adTrimmedString;

/*! Decodes a previously URL encoded string. */
- (NSString *)adUrlFormDecode;

/*! Encodes the string to pass it as a URL agrument. */
- (NSString *)adUrlFormEncode;

/*! Compares two strings, returning YES, if they are both nil. */
+ (BOOL) adSame: (NSString*) string1
       toString: (NSString*) string2;

/*! Converts base64 String to NSData */
+ (NSData *) adBase64URLDecodeData:(NSString *)encodedString;

/*! Converts NSData to base64 String */
+ (NSString *) adBase64URLEncodeData:(NSData *)data;

- (NSString*) adComputeSHA256;

@end
