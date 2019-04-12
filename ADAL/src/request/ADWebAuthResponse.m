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


#import "ADWebAuthResponse.h"
#import "ADWebResponse.h"
#import "ADWebAuthRequest.h"
#import "ADClientMetrics.h"
#import "NSString+MSIDTelemetryExtensions.h"
#import "MSIDTelemetryEventStrings.h"
#import "MSIDPkeyAuthHelper.h"
#import "NSError+MSIDExtensions.h"

@implementation ADWebAuthResponse

static NSString *const kPKeyAuthName = @"PKeyAuth";

+ (void)processError:(NSError *)error
             request:(ADWebAuthRequest *)request
          completion:(ADWebResponseCallback)completionBlock
{
    ADWebAuthResponse* response = [ADWebAuthResponse new];
    response->_request = request;
    
    [response handleNSError:error completionBlock:completionBlock];
}


+ (void)processResponse:(ADWebResponse *)webResponse
                request:(ADWebAuthRequest *)request
             completion:(ADWebResponseCallback)completionBlock
{
    ADWebAuthResponse* response = [ADWebAuthResponse new];
    response->_request = request;
    
    [response handleResponse:webResponse completionBlock:completionBlock];
}


// Decodes the parameters that come in the Authorization header. We expect them in the following
// format:
//
// <key>="<value>", key="<value>", key="<value>"
// i.e. version="1.0",CertAuthorities="OU=MyOrganization,CN=MyThingy,DN=windows,DN=net,Context="context!"
//
// This parser is lenient on whitespace, and on the presence of enclosing quotation marks. It also
// will allow commented out quotation marks
+ (NSDictionary *)parseAuthHeader:(NSString *)authHeader
{
    if (!authHeader)
    {
        return nil;
    }
    
    NSMutableDictionary* params = [NSMutableDictionary new];
    NSUInteger strLength = [authHeader length];
    NSRange currentRange = NSMakeRange(0, strLength);
    NSCharacterSet* whiteChars = [NSCharacterSet whitespaceAndNewlineCharacterSet];
    NSCharacterSet* alphaNum = [NSCharacterSet alphanumericCharacterSet];
    
    while (currentRange.location < strLength)
    {
        // Eat up any whitepace at the beginning
        while (currentRange.location < strLength && [whiteChars characterIsMember:[authHeader characterAtIndex:currentRange.location]])
        {
            ++currentRange.location;
            --currentRange.length;
        }
        
        if (currentRange.location == strLength)
        {
            return params;
        }
        
        if (![alphaNum characterIsMember:[authHeader characterAtIndex:currentRange.location]])
        {
            // malformed string
            return nil;
        }
        
        // Find the key
        NSUInteger found = [authHeader rangeOfString:@"=" options:0 range:currentRange].location;
        // If there are no keys left then exit out
        if (found == NSNotFound)
        {
            // If there still is string left that means it's malformed
            if (currentRange.length > 0)
            {
                return nil;
            }
            
            // Otherwise we're at the end, return params
            return params;
        }
        NSUInteger length = found - currentRange.location;
        NSString* key = [authHeader substringWithRange:NSMakeRange(currentRange.location, length)];
        
        // don't want the '='
        ++length;
        currentRange.location += length;
        currentRange.length -= length;
        
        NSString* value = nil;
        
        
        if ([authHeader characterAtIndex:currentRange.location] == '"')
        {
            ++currentRange.location;
            --currentRange.length;
            
            found = currentRange.location;
            
            do {
                NSRange range = NSMakeRange(found, strLength - found);
                found = [authHeader rangeOfString:@"\"" options:0 range:range].location;
            } while (found != NSNotFound && [authHeader characterAtIndex:found-1] == '\\');
            
            // If we couldn't find a matching closing quote then we have a malformed string and return NULL
            if (found == NSNotFound)
            {
                return nil;
            }
            
            length = found - currentRange.location;
            value = [authHeader substringWithRange:NSMakeRange(currentRange.location, length)];
            
            ++length;
            currentRange.location += length;
            currentRange.length -= length;
            
            // find the next comma
            found = [authHeader rangeOfString:@"," options:0 range:currentRange].location;
            if (found != NSNotFound)
            {
                length = found - currentRange.location;
            }
            
        }
        else
        {
            found = [authHeader rangeOfString:@"," options:0 range:currentRange].location;
            // If we didn't find the comma that means we're at the end of the list
            if (found == NSNotFound)
            {
                length = currentRange.length;
            }
            else
            {
                length = found - currentRange.location;
            }
            
            value = [authHeader substringWithRange:NSMakeRange(currentRange.location, length)];
        }
        
        NSString* existingValue = [params valueForKey:key];
        if (existingValue)
        {
            [params setValue:[existingValue stringByAppendingFormat:@".%@", value] forKey:key];
        }
        else
        {
            [params setValue:value forKey:key];
        }
        
        ++length;
        currentRange.location += length;
        currentRange.length -= length;
    }
    
    
    return params;
}

- (id)init
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _responseDictionary = [NSMutableDictionary new];
    
    return self;
}

- (void)checkCorrelationId:(ADWebResponse*)webResponse
{
    NSDictionary* headers = webResponse.headers;
    //In most cases the correlation id is returned as a separate header
    NSString* responseCorrelationId = [headers objectForKey:MSID_OAUTH2_CORRELATION_ID_REQUEST_VALUE];
    if (![NSString msidIsStringNilOrBlank:responseCorrelationId])
    {
        [_responseDictionary setObject:responseCorrelationId forKey:MSID_OAUTH2_CORRELATION_ID_RESPONSE];//Add it to the dictionary to be logged and checked later.
    }
}

- (void)handleResponse:(ADWebResponse *)webResponse
       completionBlock:(ADWebResponseCallback)completionBlock
{
    [self checkCorrelationId:webResponse];
    [_responseDictionary setObject:webResponse.URL forKey:@"url"];
    
    NSInteger statusCode = webResponse.statusCode;
    
    if (statusCode == 200)
    {
        if (_request.returnRawResponse)
        {
            NSString *rawResponse = [[NSString alloc] initWithData:webResponse.body encoding:NSUTF8StringEncoding];
            [_responseDictionary setObject:rawResponse forKey:@"raw_response"];
            
            completionBlock(nil, _responseDictionary);
            return;
        }
        else
        {
            [self handleJSONResponse:webResponse completionBlock:completionBlock];
            return;
        }
    }
    
    if (statusCode == 400 || statusCode == 401)
    {
        NSString *wwwAuthValue = [webResponse.headers valueForKey:@"WWW-Authenticate"];
        
        if (![NSString msidIsStringNilOrBlank:wwwAuthValue] && [wwwAuthValue containsString:kPKeyAuthName])
        {
            [self handlePKeyAuthChallenge:wwwAuthValue
                               completion:completionBlock];
            return;
        }
        
        if (!_request.acceptOnlyOKResponse)
        {
            [self handleJSONResponse:webResponse completionBlock:completionBlock];
            return;
        }
    }
    
    if (_request.retryIfServerError && statusCode >= 500 && statusCode <= 599)
    {
        _request.retryIfServerError = NO;
        //retry once after half second
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            [_request resend];
        });
        return;
    }
    
    // Request failure
    NSString* body = [[NSString alloc] initWithData:webResponse.body encoding:NSUTF8StringEncoding];
    NSString* errorData = [NSString stringWithFormat:@"Full response: %@", body];
    
    MSID_LOG_WARN(_request, @"HTTP Error %ld", (long)webResponse.statusCode);
    MSID_LOG_WARN_PII(_request, @"%@", errorData);
    
    ADAuthenticationError* adError = [ADAuthenticationError errorFromHTTPErrorCode:webResponse.statusCode
                                                                              body:[NSString stringWithFormat:@"(%lu bytes)", (unsigned long)webResponse.body.length]
                                                                           headers:webResponse.headers
                                                                     correlationId:_request.correlationId];
    
    //Now add the information to the dictionary, so that the parser can extract it:
    [self handleADError:adError completionBlock:completionBlock];
}

- (void)handleJSONResponse:(ADWebResponse*)webResponse
           completionBlock:(ADWebResponseCallback)completionBlock
{
    NSError   *jsonError  = nil;
    id         jsonObject = [NSJSONSerialization JSONObjectWithData:webResponse.body options:0 error:&jsonError];
    
    if (!jsonObject)
    {
        [self handleJSONError:jsonError body:webResponse.body completionBlock:completionBlock];
        return;
    }
    
    if (![jsonObject isKindOfClass:[NSDictionary class]])
    {
        ADAuthenticationError* adError =
        [ADAuthenticationError unexpectedInternalError:[NSString stringWithFormat:@"Unexpected object type: %@", [jsonObject class]]
                                         correlationId:_request.correlationId];
        [self handleADError:adError completionBlock:completionBlock];
        return;
    }
    
    // Load the response
    [_responseDictionary addEntriesFromDictionary:(NSDictionary*)jsonObject];
    
    NSString *clientTelemetry = [webResponse headers][ADAL_CLIENT_TELEMETRY];
    
    if (![NSString msidIsStringNilOrBlank:clientTelemetry])
    {
        NSString *speInfo = [clientTelemetry msidParsedClientTelemetry][MSID_TELEMETRY_KEY_SPE_INFO];
        
        if (![NSString msidIsStringNilOrBlank:speInfo])
        {
            [_responseDictionary setObject:speInfo forKey:MSID_TELEMETRY_KEY_SPE_INFO];
        }
    }
    
    [self handleSuccess:completionBlock];
    return;
}

- (void)handlePKeyAuthChallenge:(NSString *)wwwAuthHeaderValue
                     completion:(ADWebResponseCallback)completionBlock
{
    //pkeyauth word length=8 + 1 whitespace
    wwwAuthHeaderValue = [wwwAuthHeaderValue substringFromIndex:[kPKeyAuthName length] + 1];
    
    NSDictionary* authHeaderParams = [ADWebAuthResponse parseAuthHeader:wwwAuthHeaderValue];
    
    if (!authHeaderParams)
    {
        MSID_LOG_ERROR(_request, @"Unparseable wwwAuthHeader received");
        MSID_LOG_ERROR_PII(_request, @"Unparseable wwwAuthHeader received %@", wwwAuthHeaderValue);
    }
    
    NSString* authHeader = [MSIDPkeyAuthHelper createDeviceAuthResponse:[[_request URL] absoluteString]
                                                          challengeData:authHeaderParams
                                                                context:_request];
    
    // Add Authorization response header to the headers of the request
    [_request setAuthorizationHeader:authHeader];
    [_request resend];
}

- (void)handleSuccess:(ADWebResponseCallback)completionBlock
{
    [[ADClientMetrics getInstance] endClientMetricsRecord:[[_request URL] absoluteString]
                                                startTime:[_request startTime]
                                            correlationId:_request.correlationId
                                             errorDetails:nil];
    
    completionBlock(nil, _responseDictionary);
}

#pragma mark -
#pragma mark Error Handlers

- (void)handleJSONError:(NSError*)jsonError
                   body:(NSData*)body
        completionBlock:(ADWebResponseCallback)completionBlock
{
    
    // Unrecognized JSON response
    // We're often seeing the JSON parser being asked to parse whole HTML pages.
    // Logging out the whole thing is unhelpful as it contains no useful info.
    // If the body is > 1 KB then it's a pretty safe bet that it contains more
    // noise then would be helpful
    NSString* bodyStr = nil;
    
    if (body.length == 0)
    {
        MSID_LOG_ERROR(_request, @"Empty body received, expected JSON response. Error code: %ld", (long)jsonError.code);
    }
    else
    {
        if ([body length] < 1024)
        {
            bodyStr = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
        }
        else
        {
            bodyStr = [[NSString alloc] initWithFormat:@"large response, probably HTML, <%lu bytes>", (unsigned long)[body length]];
        }
        
        MSID_LOG_ERROR(_request, @"JSON deserialization error:");
        MSID_LOG_ERROR_PII(_request, @"JSON deserialization error: %@ - %@", jsonError.description, bodyStr);
    }
    
    [self handleNSError:jsonError completionBlock:completionBlock];
}

- (void)handleNSError:(NSError*)error
      completionBlock:(ADWebResponseCallback)completionBlock
{
    if ([[error domain] isEqualToString:@"NSURLErrorDomain"] && [error code] == -1002)
    {
        // Unsupported URL Error
        // This can happen because the redirect URI isn't a valid URI, or we've tried to jump out of the app with a URL scheme handler
        // It's worth peeking into this error to see if we have useful information anyways.
        
        NSString* url = [[error userInfo] objectForKey:@"NSErrorFailingURLKey"];
        [_responseDictionary setObject:url forKey:@"url"];
    }
    
    MSID_LOG_WARN(_request, @"System error while making request");
    
    error = [error msidErrorWithFilteringOptions:MSIDErrorFilteringOptionRemoveUrlParameters];
    
    MSID_LOG_WARN_PII(_request, @"System error while making request %@", error.description);

    // System error
    ADAuthenticationError* adError = [ADAuthenticationError errorFromNSError:error
                                                                errorDetails:error.localizedDescription
                                                               correlationId:_request.correlationId];
    
    [self handleADError:adError completionBlock:completionBlock];
}

- (void)handleADError:(ADAuthenticationError*)adError
      completionBlock:(ADWebResponseCallback)completionBlock
{
    [[ADClientMetrics getInstance] endClientMetricsRecord:[[_request URL] absoluteString]
                                                startTime:[_request startTime]
                                            correlationId:_request.correlationId
                                             errorDetails:[adError errorDetails]];
    
    completionBlock(adError, _responseDictionary);
}

@end
