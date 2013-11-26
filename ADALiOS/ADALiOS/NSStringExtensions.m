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

#import "NSStringExtensions.h"

@implementation NSString ( IPAL )

+ (BOOL)isNilOrEmpty:(NSString *)string
{
    if ( string == nil || string.length == 0 )
        return YES;
    
    return NO;
}

// application/x-form-urlencode encoding
- (NSString *)URLFormEncode
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

// application/x-form-urlencode decoding
- (NSString *)URLFormDecode
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

@end
