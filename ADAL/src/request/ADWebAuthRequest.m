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

#import "ADWebAuthRequest.h"
#import "ADWorkplaceJoinConstants.h"
#import "ADClientMetrics.h"
#import "NSDictionary+ADExtensions.h"
#import "ADOAuth2Constants.h"
#import "ADWebResponse.h"
#import "ADPkeyAuthHelper.h"

@implementation ADWebAuthRequest

@synthesize returnRawResponse = _returnRawResponse;

- (id)initWithURL:(NSURL *)url
    correlationId:(NSUUID *)correlationId
{
    self = [super initWithURL:url correlationId:correlationId];
    if (!self)
    {
        return nil;
    }
    
    [self.headers setObject:@"application/json" forKey:@"Accept"];
    [self.headers setObject:@"application/x-www-form-urlencoded" forKey:@"Content-Type"];
    [self.headers setObject:pKeyAuthHeaderVersion forKey:pKeyAuthHeader];
    
    _retryIfServerError = YES;
    
    return self;
}

- (void)setRequestDictionary:(NSDictionary*)requestDictionary
{
    if (requestDictionary == _requestDictionary)
    {
        return;
    }
    
    SAFE_ARC_RELEASE(_requestDictionary);
    _requestDictionary = [requestDictionary copy];
}

- (void)sendRequest:(void (^)(NSDictionary *))completionBlock
{
    if ([self isGetRequest])
    {
        NSString* newURL = [NSString stringWithFormat:@"%@?%@", [_requestURL absoluteString], [_requestDictionary adURLFormEncode]];
        SAFE_ARC_RELEASE(_requestURL);
        _requestURL = [NSURL URLWithString:newURL];
        SAFE_ARC_RETAIN(_requestURL);
    }

    [self setBody:[[_requestDictionary adURLFormEncode] dataUsingEncoding:NSUTF8StringEncoding]];
    
    _startTime = [NSDate new];
    [[ADClientMetrics getInstance] addClientMetrics:self.headers endpoint:[_requestURL absoluteString]];
    
    [self send:^( NSError *error, ADWebResponse *webResponse )
    {
        _responseDictionary = [NSMutableDictionary new];
        if (error)
        {
            [self handleNSError:error
                completionBlock:completionBlock];
        }
        else
        {
            [self handleResponse:webResponse completionBlock:completionBlock];
        }
        
        SAFE_ARC_RELEASE(_responseDictionary);
        _responseDictionary = nil;
    }];
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
       completionBlock:(void (^)(NSDictionary *))completionBlock
{
    [self checkCorrelationId:webResponse];
    [_responseDictionary setObject:webResponse.URL forKey:@"url"];
    
    switch (webResponse.statusCode)
    {
        case 200:
            if(_returnRawResponse)
            {
                NSString* rawResponse = [[NSString alloc] initWithData:webResponse.body encoding:NSASCIIStringEncoding];
                [_responseDictionary setObject:rawResponse
                                        forKey:@"raw_response"];
                SAFE_ARC_RELEASE(rawResponse);
                break;
            }
        case 400:
        case 401:
        {
            if(!_handledPkeyAuthChallenge)
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
        {
            //retry if it is a server error
            //500 and 503 are the ones we retry
            if (_retryIfServerError)
            {
                _retryIfServerError = NO;
                //retry once after half second
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                    [self sendRequest:completionBlock];
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
           completionBlock:(void (^)(NSDictionary *))completionBlock
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
                     completion:(void (^)(NSDictionary *))completionBlock
{
    //pkeyauth word length=8 + 1 whitespace
    wwwAuthHeaderValue = [wwwAuthHeaderValue substringFromIndex:[pKeyAuthName length] + 1];
    
    NSDictionary* authHeaderParams = [wwwAuthHeaderValue authHeaderParams];
    
    if (!authHeaderParams)
    {
        AD_LOG_ERROR_F(@"Unparseable wwwAuthHeader received.", AD_ERROR_SERVER_WPJ_REQUIRED, _correlationId, @"%@", wwwAuthHeaderValue);
    }
    
    NSString* authHeader = [ADPkeyAuthHelper createDeviceAuthResponse:[_requestURL absoluteString]
                                                        challengeData:authHeaderParams];
    
    // Add Authorization response header to the headers of the request
    [self.headers setObject:authHeader forKey:@"Authorization"];
    
    [self sendRequest:completionBlock];
}

- (void)handleSuccess:(void (^)(NSDictionary *))completionBlock
{
    [[ADClientMetrics getInstance] endClientMetricsRecord:[_requestURL absoluteString]
                                                startTime:_startTime
                                            correlationId:_correlationId
                                             errorDetails:nil];
    SAFE_ARC_RELEASE(_startTime);
    _startTime = nil;
    
    completionBlock(_responseDictionary);
}

#pragma mark -
#pragma mark Error Handlers

- (void)handleJSONError:(NSError*)jsonError
                   body:(NSData*)body
        completionBlock:(void (^)(NSDictionary *))completionBlock
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

- (void)handleNSError:(NSError*)error completionBlock:(void (^)(NSDictionary*))completionBlock
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

- (void)handleADError:(ADAuthenticationError*)adError completionBlock:(void (^)(NSDictionary*))completionBlock
{
    [_responseDictionary setObject:adError
                            forKey:AUTH_NON_PROTOCOL_ERROR];
    
    [[ADClientMetrics getInstance] endClientMetricsRecord:[_requestURL absoluteString]
                                                startTime:_startTime
                                            correlationId:_correlationId
                                             errorDetails:[adError errorDetails]];
    
    SAFE_ARC_RELEASE(_startTime);
    _startTime = nil;
    
    completionBlock(_responseDictionary);
}

@end
