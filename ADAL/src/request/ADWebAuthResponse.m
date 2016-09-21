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
#import "ADOauth2Constants.h"
#import "ADWorkplaceJoinConstants.h"
#import "ADPKeyAuthHelper.h"
#import "ADClientMetrics.h"

@implementation ADWebAuthResponse

+ (void)processError:(NSError *)error
       correlationId:(NSUUID *)correlationId
          completion:(ADWebResponseCallback)completionBlock
{
    ADWebAuthResponse* response = [ADWebAuthResponse new];
    response->_correlationId = correlationId;
    SAFE_ARC_RETAIN(correlationId);
    
    [response handleNSError:error completionBlock:completionBlock];
}


+ (void)processResponse:(ADWebResponse *)webResponse
                request:(ADWebAuthRequest *)request
             completion:(ADWebResponseCallback)completionBlock
{
    ADWebAuthResponse* response = [ADWebAuthResponse new];
    response->_request = request;
    SAFE_ARC_RETAIN(request);
    
    NSUUID* correlationId = request.correlationId;
    SAFE_ARC_RETAIN(correlationId);
    response->_correlationId = correlationId;
    
    [response handleResponse:webResponse completionBlock:completionBlock];
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


- (void)dealloc
{
    SAFE_ARC_RELEASE(_responseDictionary);
    SAFE_ARC_RELEASE(_request);
    SAFE_ARC_RELEASE(_correlationId);
    SAFE_ARC_SUPER_DEALLOC();
}

- (void)checkCorrelationId:(ADWebResponse*)webResponse
{
    NSDictionary* headers = webResponse.headers;
    //In most cases the correlation id is returned as a separate header
    NSString* responseCorrelationId = [headers objectForKey:OAUTH2_CORRELATION_ID_REQUEST_VALUE];
    if (![NSString adIsStringNilOrBlank:responseCorrelationId])
    {
        [_responseDictionary setObject:responseCorrelationId forKey:OAUTH2_CORRELATION_ID_RESPONSE];//Add it to the dictionary to be logged and checked later.
    }
}

- (void)handleResponse:(ADWebResponse *)webResponse
       completionBlock:(ADWebResponseCallback)completionBlock
{
    [self checkCorrelationId:webResponse];
    [_responseDictionary setObject:webResponse.URL forKey:@"url"];
    
    switch (webResponse.statusCode)
    {
        case 200:
            if(_request.returnRawResponse)
            {
                NSString* rawResponse = [[NSString alloc] initWithData:webResponse.body encoding:NSUTF8StringEncoding];
                [_responseDictionary setObject:rawResponse
                                        forKey:@"raw_response"];
                SAFE_ARC_RELEASE(rawResponse);
                break;
            }
        case 400:
        case 401:
        {
            if(!_request.handledPkeyAuthChallenge)
            {
                NSString* wwwAuthValue = [webResponse.headers valueForKey:wwwAuthenticateHeader];
                if(![NSString adIsStringNilOrBlank:wwwAuthValue] && [wwwAuthValue adContainsString:pKeyAuthName])
                {
                    [self handlePKeyAuthChallenge:wwwAuthValue
                                       completion:completionBlock];
                    return;
                }
            }
            
            [self handleJSONResponse:webResponse completionBlock:completionBlock];
            break;
        }
        case 500:
        case 503:
        case 504:
        {
            //retry if it is a server error
            //500, 503 and 504 are the ones we retry
            if (_request.retryIfServerError)
            {
                _request.retryIfServerError = NO;
                //retry once after half second
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                    [_request resend];
                });
                return;
            }
            //no "break;" here
            //will go to default for handling if "retryIfServerError" is NO
        }
        default:
        {
            // Request failure
            NSString* body = [[NSString alloc] initWithData:webResponse.body encoding:NSUTF8StringEncoding];
            NSString* errorData = [NSString stringWithFormat:@"Full response: %@", body];
            AD_LOG_WARN(([NSString stringWithFormat:@"HTTP Error %ld", (long)webResponse.statusCode]), _correlationId, errorData);
            
            ADAuthenticationError* adError = [ADAuthenticationError HTTPErrorCode:webResponse.statusCode
                                                                             body:[NSString stringWithFormat:@"(%lu bytes)", (unsigned long)webResponse.body.length]
                                                                    correlationId:_correlationId];
            SAFE_ARC_RELEASE(body);
            
            //Now add the information to the dictionary, so that the parser can extract it:
            [self handleADError:adError completionBlock:completionBlock];
        }
    }
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
                                         correlationId:_correlationId];
        [self handleADError:adError completionBlock:completionBlock];
        return;
    }
    
    // Load the response
    [_responseDictionary addEntriesFromDictionary:(NSDictionary*)jsonObject];
    [self handleSuccess:completionBlock];
    return;
}

- (void)handlePKeyAuthChallenge:(NSString *)wwwAuthHeaderValue
                     completion:(ADWebResponseCallback)completionBlock
{
    //pkeyauth word length=8 + 1 whitespace
    wwwAuthHeaderValue = [wwwAuthHeaderValue substringFromIndex:[pKeyAuthName length] + 1];
    
    NSDictionary* authHeaderParams = [wwwAuthHeaderValue authHeaderParams];
    
    if (!authHeaderParams)
    {
        AD_LOG_ERROR_F(@"Unparseable wwwAuthHeader received.", AD_ERROR_SERVER_WPJ_REQUIRED, _correlationId, @"%@", wwwAuthHeaderValue);
    }
    
    ADAuthenticationError* adError = nil;
    NSString* authHeader = [ADPkeyAuthHelper createDeviceAuthResponse:[[_request URL] absoluteString]
                                                        challengeData:authHeaderParams
                                                        correlationId:_correlationId
                                                                error:&adError];
    
    if (!authHeader)
    {
        [self handleADError:adError completionBlock:completionBlock];
        return;
    }
    
    // Add Authorization response header to the headers of the request
    [_request.headers setObject:authHeader forKey:@"Authorization"];
    
    [_request resend];
}

- (void)handleSuccess:(ADWebResponseCallback)completionBlock
{
    [[ADClientMetrics getInstance] endClientMetricsRecord:[[_request URL] absoluteString]
                                                startTime:[_request startTime]
                                            correlationId:_correlationId
                                             errorDetails:nil];
    
    completionBlock(_responseDictionary);
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
        AD_LOG_ERROR(@"Empty body received, expected JSON response.", jsonError.code, _correlationId, nil);
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
        
        NSString* errorMsg = [NSString stringWithFormat:@"JSON deserialization error: %@", jsonError.description];
        
        AD_LOG_ERROR_F(errorMsg, jsonError.code, _correlationId, @"%@", bodyStr);
        SAFE_ARC_RELEASE(bodyStr);
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
    
    AD_LOG_WARN(@"System error while making request.", _correlationId, error.description);
    // System error
    ADAuthenticationError* adError = [ADAuthenticationError errorFromNSError:error
                                                                errorDetails:error.localizedDescription
                                                               correlationId:_correlationId];
    
    [self handleADError:adError completionBlock:completionBlock];
}

- (void)handleADError:(ADAuthenticationError*)adError
      completionBlock:(ADWebResponseCallback)completionBlock
{
    [_responseDictionary setObject:adError
                            forKey:AUTH_NON_PROTOCOL_ERROR];
    
    [[ADClientMetrics getInstance] endClientMetricsRecord:[[_request URL] absoluteString]
                                                startTime:[_request startTime]
                                            correlationId:_correlationId
                                             errorDetails:[adError errorDetails]];
    
    completionBlock(_responseDictionary);
}

@end
