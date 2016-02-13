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

/*! Returns YES if the passed string is contained. Throws if the passed
 argument is nil or empty string.
 @param cotnained:The string to search
 */
- (BOOL)adContainsString:(NSString *)contained;

/*! Returns the same string, but without the leading and trailing whitespace */
- (NSString *)adTrimmedString;

/*! Goes over the string starting at "start" index and skips all characters that are
 not in the passed set. Returns the index of the first occurence, or just beyond the end
 (self.length) if not found. If start is beyond the end of the string, the method returns
 index just beyond the end (self.length).
 @param set: The set of characters to find. E.g. [NSCharacterSet whitespaceAndNewlineCharacterSet]
 @param start: The character index where to start searching. */
- (long)adFindCharactersFromSet: (NSCharacterSet*) set
                        start: (long) startIndex;

/*! Calls adFindCharactersFromSet with the non-white character set. */
- (long)adFindNonWhiteCharacterAfter: (long) startIndex;

/*! Calls adFindCharactersFromSet with a single character set */
- (long)adFindCharacter:(unichar)toFind start: (long) startIndex;

/*! Ensures that the specified range within the string starts with the prefixWord,
 and the prefixWord is followed by a white space character, or the range terminates
 right after the prefixWord.
 */
- (BOOL)adRangeHasPrefixWord:(NSString *)prefixWord
                       range:(NSRange)range;

/*! Calls adRangeHasPrefixWord with the range of the substring from "substringStart"
 till the end of the string */
- (BOOL)adSubstringHasPrefixWord:(NSString *)prefixWord
                           start:(long)substringStart;

/*! Decodes a previously URL encoded string. */
- (NSString *)adUrlFormDecode;

/*! Encodes the string to pass it as a URL agrument. */
- (NSString *)adUrlFormEncode;

/*! Compares two strings, returning YES, if they are both nil. */
+ (BOOL)adSame:(NSString *)string1
      toString:(NSString *)string2;

/*! Converts base64 String to NSData */
+ (NSData *)Base64DecodeData:(NSString *)encodedString;

/*! Converts NSData to base64 String */
+ (NSString *)Base64EncodeData:(NSData *)data;

- (NSString*)adComputeSHA256;

- (NSDictionary*)authHeaderParams;

@end
