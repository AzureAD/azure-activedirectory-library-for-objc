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
#import "ADALiOS.h"
#import <CommonCrypto/CommonDigest.h>

static NSCharacterSet* _nonWhitespaceCharacterSet()
{
    static dispatch_once_t once;
    static NSCharacterSet* characterSet;
    dispatch_once(&once, ^{
        characterSet = [[NSCharacterSet whitespaceAndNewlineCharacterSet] invertedSet];
    });
    return characterSet;
}

@implementation NSString (ADHelperMethods)

- (NSString *)adBase64UrlDecode
{
    NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:self options:0];
    
    return [[NSString alloc] initWithData:decodedData encoding:NSUTF8StringEncoding];
}

// Base64 URL encodes a string
- (NSString *)adBase64UrlEncode
{
    return [[self dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0];
}

+ (BOOL)adIsStringNilOrBlank:(NSString*)string
{
    NSUInteger length = [string length];
    if (!string || length == 0)
    {
        return YES;
    }
   
    NSRange whitespace = [string rangeOfCharacterFromSet:_nonWhitespaceCharacterSet()];
    return (whitespace.location == NSNotFound);
};

- (BOOL)adContainsString:(NSString*)contained
{
    if (!contained || !contained.length)
    {
        return YES;
    }
    
    return [self rangeOfString:contained].location != NSNotFound;
}
- (NSString*)adTrimmedString
{
    //The white characters set is cached by the system:
    NSCharacterSet* set = [NSCharacterSet whitespaceAndNewlineCharacterSet];
    return [self stringByTrimmingCharactersInSet:set];
}

- (NSString *)adUrlFormDecode
{
    // Two step decode: first replace + with a space, then percent unescape
    CFMutableStringRef decodedString = CFStringCreateMutableCopy( NULL, 0, (__bridge CFStringRef)self );
    CFStringFindAndReplace( decodedString, CFSTR("+"), CFSTR(" "), CFRangeMake( 0, CFStringGetLength( decodedString ) ), kCFCompareCaseInsensitive );
    
    CFStringRef unescapedString = CFURLCreateStringByReplacingPercentEscapesUsingEncoding( NULL,                    // Allocator
                                                                                          decodedString,           // Original string
                                                                                          CFSTR(""),               // Characters to leave escaped
                                                                                          kCFStringEncodingUTF8 ); // Encoding
    CFRelease( decodedString );
    
    return CFBridgingRelease(unescapedString);
}

- (NSString *)adUrlFormEncode
{
    // Two step encode: first percent escape everything except spaces, then convert spaces to +
    CFStringRef escapedString = CFURLCreateStringByAddingPercentEscapes( NULL,                         // Allocator
                                                                        (__bridge CFStringRef)self,            // Original string
                                                                        CFSTR(" "),                   // Characters to leave unescaped
                                                                        CFSTR("!#$&'()*+,/:;=?@[]%"), // Legal Characters to be escaped
                                                                        kCFStringEncodingUTF8 );      // Encoding
    
    // Replace spaces with +
    CFMutableStringRef encodedString = CFStringCreateMutableCopy( NULL, 0, escapedString );
    CFStringFindAndReplace( encodedString, CFSTR(" "), CFSTR("+"), CFRangeMake( 0, CFStringGetLength( encodedString ) ), kCFCompareCaseInsensitive );
    
    CFRelease( escapedString );
    
    return CFBridgingRelease( encodedString );
}

+ (BOOL)adSame:(NSString*)string1
      toString:(NSString*)string2
{
    if (!string1)
        return !string2; //if both are nil, they are equal
    else
        return [string1 isEqualToString:string2];
}


- (NSString*)adComputeSHA256
{
    const char* inputStr = [self UTF8String];
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(inputStr, (int)strlen(inputStr), hash);
    NSMutableString* toReturn = [[NSMutableString alloc] initWithCapacity:CC_SHA256_DIGEST_LENGTH*2];
    for (int i = 0; i < sizeof(hash)/sizeof(hash[0]); ++i)
    {
        [toReturn appendFormat:@"%02x", hash[i]];
    }
    return toReturn;
}

@end
