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

#import "ADAL_Internal.h"
#import "ADAuthenticationParameters.h"
#import "ADAuthenticationParameters+Internal.h"

NSString* const OAuth2_Bearer  = @"Bearer";
NSString* const OAuth2_Authenticate_Header = @"WWW-Authenticate";
NSString* const OAuth2_Authorization_Uri  = @"authorization_uri";
NSString* const OAuth2_Resource_Id = @"resource_id";

NSString* const MissingHeader = @"The authentication header '%@' is missing in the Unauthorized (401) response. Make sure that the resouce server supports OAuth2 protocol.";
NSString* const MissingOrInvalidAuthority = @"The authentication header '%@' in the Unauthorized (401) response does not contain valid '%@' parameter. Make sure that the resouce server supports OAuth2 protocol.";
NSString* const InvalidHeader = @"The authentication header '%@' for the Unauthorized (401) response cannot be parsed. Header value: %@";
NSString* const ConnectionError = @"Connection error: %@";
NSString* const InvalidResponse = @"Missing or invalid Url response.";
NSString* const UnauthorizedHTTStatusExpected = @"Unauthorized (401) HTTP status code is expected, but the actual status code is %d";
const unichar Quote = '\"';
// Bearer's parameters extration regex.
NSString* const ExtractionExpression = @"\\s*([^,\\s=\"]+?)\\s*=\\s*\"([^\"]*?)\"\\s*";

@implementation ADAuthenticationParameters (Internal)


- (id)initInternalWithParameters:(NSDictionary *)extractedParameters
                           error:(ADAuthenticationError * __autoreleasing *)error;

{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    if (!extractedParameters)
    {
        return nil;
    }
    
    NSString* authority = [extractedParameters objectForKey:OAuth2_Authorization_Uri];
    NSURL* testUrl = [NSURL URLWithString:authority];//Nil argument returns nil
    if (!testUrl)
    {
        NSString* errorDetails = [NSString stringWithFormat:MissingOrInvalidAuthority,
                                  OAuth2_Authenticate_Header, OAuth2_Authorization_Uri];
        ADAuthenticationError* adError = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_SERVER_AUTHENTICATE_HEADER_BAD_FORMAT
                                                                                protocolCode:nil
                                                                                errorDetails:errorDetails
                                                                               correlationId:nil];
        if (error)
        {
            *error = adError;
        }
        return nil;
    }
    
    _extractedParameters = extractedParameters;
    _authority = authority;
    _resource = [_extractedParameters objectForKey:OAuth2_Resource_Id];
    return self;
}

//Generates and returns an error
+ (ADAuthenticationError *)invalidHeader:(NSString *)headerContents
{
    NSString* errorDetails = [NSString stringWithFormat:InvalidHeader,
     OAuth2_Authenticate_Header, headerContents];
    return [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_SERVER_AUTHENTICATE_HEADER_BAD_FORMAT
                                                  protocolCode:nil
                                                   errorDetails:errorDetails
                                                  correlationId:nil];
}

+ (NSDictionary *)extractChallengeParameters:(NSString *)headerContents
                                       error:(ADAuthenticationError * __autoreleasing *)error;
{
    NSMutableArray<NSString *> *items = [self extractItems:headerContents];
    
    // Find start index of bearer and verify that there is only 1 bearer challendge in the string.
    NSInteger bearerStartIndex = NSNotFound;
    for (int i = 0; i < items.count; i++)
    {
        NSString *item = items[i];
        NSRange range = [item rangeOfString:@"\\s*Bearer\\s+([^,\\s=\"]+?)\\s*=\\s*\"([^\"]*?)\"" options:NSRegularExpressionSearch];
        if (range.location != NSNotFound)
        {
            if (bearerStartIndex != NSNotFound)
            {
                // Bearer was alredy found, this one is 2nd bearere in the string.
                // That's not allowed. Reset index and break cycle.
                bearerStartIndex = NSNotFound;
                break;
            }
            
            // Remove 'Bearer'.
            NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"\\s*Bearer\\s+" options:NSRegularExpressionCaseInsensitive error:nil];
            NSString *param = [regex stringByReplacingMatchesInString:item options:0 range:NSMakeRange(0, [item length]) withTemplate:@""];
            
            // Save cleared param.
            items[i] = param;
            
            // Save bearer's start index.
            bearerStartIndex = i;
        }
    }
    
    // Bearer was not found.
    if (bearerStartIndex == NSNotFound)
    {
        *error = [self invalidHeader:headerContents];
        return nil;
    }

    NSMutableDictionary *parameters = [self extractParameters:items[bearerStartIndex]];
    
    for (NSInteger i = bearerStartIndex; i < items.count; i++)
    {
        NSString *item = items[i];
        
        if (![self isParameter:item])
        {
            break;
        }
        
        NSMutableDictionary *nextParameters = [self extractParameters:items[i]];
        [parameters addEntriesFromDictionary:nextParameters];
    }
    
    return parameters;
}

#pragma mark - Private

+ (NSMutableArray *)extractItems:(NSString *)string
{
    NSMutableArray *items = [NSMutableArray new];
    
    NSInteger rightIndex = 0;
    NSInteger leftIndex = 0;
    while (rightIndex < string.length)
    {
        unichar c = [string characterAtIndex:rightIndex];
        
        // Start of a quaoted string, lets get last index of it and continue iteration.
        if (c == '"' || c == '\'')
        {
            rightIndex = [self quotedStringLastIndex:string startIndex:rightIndex];
            rightIndex++;
            continue;
        }
        
        if (c == ',')
        {
            NSUInteger len = rightIndex - leftIndex;
            NSRange range = NSMakeRange(leftIndex, len);
            NSString *item = [string substringWithRange:range];
            
            [items addObject:item];
            
            leftIndex = rightIndex + 1;
        }
        
        rightIndex++;
    }
    
    if (leftIndex < rightIndex)
    {
        NSUInteger len = rightIndex - leftIndex;
        NSRange range = NSMakeRange(leftIndex, len);
        NSString *item = [string substringWithRange:range];
        
        [items addObject:item];
    }
    
    // Check for invalid parameters/state.
    if (leftIndex == rightIndex)
    {
        // Comma was not followed by a text -- invalid header.
        return nil;
    }
    
    for (NSString *item in items) {
        if ([NSString adIsStringNilOrBlank:item]) {
            // Blank item found -- invalid header.
            return nil;
        }
    }
    
    return items;
}

+ (NSUInteger)quotedStringLastIndex:(NSString *)headerContents startIndex:(NSUInteger)startIndex
{
    NSUInteger lastIndex = startIndex;
    
    unichar quotedChar = [headerContents characterAtIndex:startIndex];
    if (quotedChar == '"' || quotedChar == '\'')
    {
        NSUInteger nextIndex = startIndex + 1;
        while (nextIndex < headerContents.length) {
            unichar c = [headerContents characterAtIndex:nextIndex];
            
            if (c == quotedChar) {
                lastIndex = nextIndex;
                break;
            }
            
            nextIndex++;
        }
    }
    
    return lastIndex;
}

+ (BOOL)isParameter:(NSString *)string
{
    NSRange range = [string rangeOfString:ExtractionExpression options:NSRegularExpressionSearch];
    return range.location == 0;
}

+ (NSMutableDictionary *)extractParameters:(NSString *)string
{
    NSMutableDictionary* parameters = [NSMutableDictionary new];
    
    NSRegularExpression* extractionRegEx = [NSRegularExpression regularExpressionWithPattern:ExtractionExpression
                                                                                     options:0
                                                                                       error:nil];
    if (extractionRegEx)
    {
        
        [extractionRegEx enumerateMatchesInString:string
                                          options:0
                                            range:NSMakeRange(0, string.length)
                                       usingBlock:^(NSTextCheckingResult *result, NSMatchingFlags flags, BOOL *stop)
         {
             (void)flags;
             (void)stop;
             
             assert(result.numberOfRanges == 3);
             
             NSRange key = [result rangeAtIndex:1];
             NSRange value = [result rangeAtIndex:2];
             if (key.length && value.length)
             {
                 [parameters setObject:[string substringWithRange:value]
                                forKey:[string substringWithRange:key]];
             }
         }];
    }
    
    return parameters;
}

@end
