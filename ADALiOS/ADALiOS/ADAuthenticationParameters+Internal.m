// Created by Boris Vidolov on 10/10/13.
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
#import "ADAuthenticationParameters+Internal.h"

NSString* const OAuth2_Bearer  = @"Bearer";
NSString* const OAuth2_Authenticate_Header = @"WWW-Authenticate";
NSString* const OAuth2_Authorization_Uri  = @"authorization_uri";
NSString* const OAuth2_Resource_Id = @"resource_id";

NSString* const MissingHeader = @"The authentication header '%@' is missing in the Unauthorized (401) response. Make sure that the resouce server supports OAuth2 protocol.";
NSString* const MissingAuthority = @"The authentication header '%@' in the Unauthorized (401) response does not contain valid '%@' parameter. Make sure that the resouce server supports OAuth2 protocol.";
NSString* const InvalidHeader_NoBearer = @"The authentication header '%@' for the Unauthorized (401) response does not start with '%@' word. Header value: %@";
NSString* const ConnectionError = @"Connection error: %@";
NSString* const InvalidResponse = @"Missing or invalid Url response.";
NSString* const UnauthorizedHTTStatusExpected = @"Expected Unauthorized (401) HTTP status code. Actual status code %d";
const unichar Quote = '\"';
const unichar Equals = '=';
const unichar Comma = ',';

@implementation ADAuthenticationParameters (Internal)

-(id) initInternalWithChallenge: (NSString*) challengeHeaderContents
                          start: (long)start;
{
    self = [super init];
    if (self)
    {
        if (![self extractChallengeItems:challengeHeaderContents start:start])
        {
            //Clear if an error occurred:
            self = nil;
        }
    }
    return self;
}

/* Challenge validation and extraction. Returns null if the challenge prefix is not present.
 Expects a valid string to be passed. */
+ (long) extractChallenge: (NSString*) headerContents
                    error: (ADAuthenticationError* __autoreleasing*) error;
{
    THROW_ON_NIL_ARGUMENT(headerContents);//We shouldn't be here in this case
    
    long start = [headerContents findNonWhiteCharacterAfter:0];

    //Requirement to have at least "Bearer ":
    if (![headerContents substringHasPrefixWord:OAuth2_Bearer start:start])
    {
        //This will log the error:
        ADAuthenticationError* bearerError =
        [ADAuthenticationError errorFromUnauthorizedResponse:AD_ERROR_AUTHENTICATE_HEADER_BAD_FORMAT
                                                errorDetails:[NSString stringWithFormat:InvalidHeader_NoBearer, OAuth2_Authenticate_Header, OAuth2_Bearer, headerContents]];
        if (error)
        {
            *error = bearerError;
        }
        return -1;
    }
    start += OAuth2_Bearer.length;
    
    return [headerContents findNonWhiteCharacterAfter:start];//Skip any additional white space
}

- (BOOL) extractChallengeItems:(NSString *)headerContents start:(long)start
{
    THROW_ON_NIL_ARGUMENT(headerContents);//The function should not be called with nil.
    
    _extractedParameters = [NSMutableDictionary new];
    long end = headerContents.length;
    
    while (start < end)
    {
        start = [headerContents findNonWhiteCharacterAfter:start];
        if (start >= end)
        {
            break;
        }
        if ([headerContents characterAtIndex:start] == Comma)
        {
            ++start;//Move beyond it to avoid infinite loop
            continue;//Handle cases of skipped parameters: ",, resourceUri = \"<..>\";
        }
        
        //The next few lines parse @"<key1>="<value1>" , <key2>="<value2>", <...> ".
        //According to the Bearer protocol, keys are non-quoted; there is no white
        //space around the equals sign and the values are quoted. Values can contain
        //commas and equals sign, but cannot contain embedded quotes.
        long equalsIndex = [headerContents findCharacter:Equals start:start];
        if (equalsIndex >= end)
        {
            break;//Reached the end
        }
        if (start >= equalsIndex - 1)
        {
            return NO;//Example @"=\"asdfa\"". Missing key.
        }
        if (equalsIndex + 1 >= end || [headerContents characterAtIndex:equalsIndex + 1] != Quote)
        {
            return NO;//Example @"foo=" or @"foo=bar; Empty value provided or missing quotes.
        }
        
        long valueStart = equalsIndex + 2;//Can be == headerContext.length.
        long secondQuote = [headerContents findCharacter:Quote start:valueStart];
        if (secondQuote >= end)
        {
            return NO;// No closing quote: Example: @"foo = \"bar"
        }
        
        if (secondQuote > valueStart)//Add only if not empty
        {
            //Ranges of the key and the value:
            NSRange key = {.location = start, .length = (equalsIndex - start)};
            NSRange value = {.location = valueStart, .length = (secondQuote - valueStart)};
            //Add the key-value pair:
            NSString* keyString = [headerContents substringWithRange:key];
            NSString* valueString = [headerContents substringWithRange:value];
            [_extractedParameters setObject: valueString
                                     forKey: keyString];
        }
        //Move to the next pair:
        start = [headerContents findNonWhiteCharacterAfter:secondQuote + 1];
        if (start < end && [headerContents characterAtIndex:start] != Comma)
        {
            return NO;// Additional values, e.g. @"foo="bar" baasdfasdf, ...";
        }
        ++start;//Beyond the comma
    }
    
    //Format is valid, extracting explictly the needed parameters:
    _authority = [_extractedParameters objectForKey:OAuth2_Authorization_Uri];
    _resource = [_extractedParameters objectForKey:OAuth2_Resource_Id];
    
    return YES;
}


@end
