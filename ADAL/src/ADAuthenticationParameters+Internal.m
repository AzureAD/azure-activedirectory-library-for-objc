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
//The regular expression that matches the Bearer contents:
NSString* const RegularExpression = @"^Bearer\\s+([^,\\s=\"]+?)=\"([^\"]*?)\"\\s*(?:,\\s*([^,\\s=\"]+?)=\"([^\"]*?)\"\\s*)*$";
NSString* const ExtractionExpression = @"\\s*([^,\\s=\"]+?)=\"([^\"]*?)\"";

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
        SAFE_ARC_RELEASE(self);
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
        SAFE_ARC_RELEASE(self);
        return nil;
    }
    
    _extractedParameters = extractedParameters;
    SAFE_ARC_RETAIN(_extractedParameters);
    _authority = authority;
    SAFE_ARC_RETAIN(_authority);
    _resource = [_extractedParameters objectForKey:OAuth2_Resource_Id];
    SAFE_ARC_RETAIN(_resource);
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
    NSError* rgError = nil;
    __block ADAuthenticationError* adError = nil;
    
    if ([NSString adIsStringNilOrBlank:headerContents])
    {
        adError = [self invalidHeader:headerContents];
    }
    else
    {
        //First check that the header conforms to the protocol:
        NSRegularExpression* overAllRegEx = [NSRegularExpression regularExpressionWithPattern:RegularExpression
                                                                                      options:0
                                                                                        error:&rgError];
        if (overAllRegEx)
        {
            long matched = [overAllRegEx numberOfMatchesInString:headerContents options:0 range:NSMakeRange(0, headerContents.length)];
            if (!matched)
            {
                adError = [self invalidHeader:headerContents];
            }
            else
            {
                //Once we know that the header is in the right format, the regex below will extract individual
                //name-value pairs. This regex is not as exclusive, so it relies on the previous check
                //to guarantee correctness:
                NSRegularExpression* extractionRegEx = [NSRegularExpression regularExpressionWithPattern:ExtractionExpression
                                                                                                 options:0
                                                                                                   error:&rgError];
                if (extractionRegEx)
                {
                    NSMutableDictionary* parameters = [NSMutableDictionary new];
                    [extractionRegEx enumerateMatchesInString:headerContents
                                                      options:0
                                                        range:NSMakeRange(0, headerContents.length)
                                                   usingBlock:^(NSTextCheckingResult *result, NSMatchingFlags flags, BOOL *stop)
                     {
                         (void)flags;
                         (void)stop;
                         
                         //Block executed for each name-value match:
                         if (result.numberOfRanges != 3)//0: whole match, 1 - name group, 2 - value group
                         {
                             //Shouldn't happen given the explicit expressions and matches, but just in case:
                             adError = [self invalidHeader:headerContents];
                         }
                         else
                         {
                             NSRange key = [result rangeAtIndex:1];
                             NSRange value = [result rangeAtIndex:2];
                             if (key.length && value.length)
                             {
                                 [parameters setObject:[headerContents substringWithRange:value]
                                                forKey:[headerContents substringWithRange:key]];
                             }
                         }
                     }];
                    return parameters;
                }
            }
        }
    }
    
    if (rgError)
    {
        //The method below will log internally the error:
        adError =[ADAuthenticationError errorFromNSError:rgError errorDetails:rgError.description correlationId:nil];
    }
    
    if (error)
    {
        *error = adError;
    }
    return nil;
}

@end
