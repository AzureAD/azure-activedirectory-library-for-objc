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

#import "ADTelemetryHttpEvent.h"
#import "ADTelemetryEventStrings.h"

@implementation ADTelemetryHttpEvent

- (void)setHttpMethod:(NSString*)method
{
    [self setProperty:TELEMETRY_HTTP_METHOD value:method];
}

- (void)setHttpPath:(NSString*)path
{
    [self setProperty:TELEMETRY_HTTP_PATH value:path];
}

- (void)setHttpResponseCode:(NSString*)code
{
    [self setProperty:TELEMETRY_HTTP_RESPONSE_CODE value:code];
}

- (void)setOAuthErrorCode:(NSString*)code
{
    [self setProperty:TELEMETRY_OAUTH_ERROR_CODE value:code];
}

- (void)setHttpResponseMethod:(NSString*)method
{
    [self setProperty:TELEMETRY_HTTP_RESPONSE_METHOD value:method];
}

- (void)setHttpRequestQueryParams:(NSString*)params
{
    [self setProperty:TELEMETRY_REQUEST_QUERY_PARAMS value:params];
}

- (void)setHttpUserAgent:(NSString*)userAgent
{
    [self setProperty:TELEMETRY_USER_AGENT value:userAgent];
}

- (void)setHttpErrorDomain:(NSString*)errorDomain
{
    [self setProperty:TELEMETRY_HTTP_ERROR_DOMAIN value:errorDomain];
}

- (void)processEvent:(NSMutableDictionary*)eventToBeDispatched
{
    [super processEvent:eventToBeDispatched];
    
    (void)eventToBeDispatched;
    
    int httpEventCount = 1;
    if ([eventToBeDispatched objectForKey:TELEMETRY_HTTP_EVENT_COUNT])
    {
        httpEventCount = [[eventToBeDispatched objectForKey:TELEMETRY_HTTP_EVENT_COUNT] intValue] + 1;
    }
    [eventToBeDispatched setObject:[NSString stringWithFormat:@"%d", httpEventCount] forKey:TELEMETRY_HTTP_EVENT_COUNT];
    
    NSArray* properties = [self getProperties];
    for (NSArray* property in properties)
    {
        if ([property[0] isEqualToString:TELEMETRY_HTTP_RESPONSE_CODE]
            ||[property[0] isEqualToString:TELEMETRY_OAUTH_ERROR_CODE]
            ||[property[0] isEqualToString:TELEMETRY_HTTP_ERROR_DOMAIN]
            ||[property[0] isEqualToString:TELEMETRY_HTTP_PATH])
        {
            [eventToBeDispatched setObject:property[1] forKey:property[0]];
        }
    }
}

- (NSString*)scrubTenantFromUrl:(NSString*)url
{
    //Scrub the tenant domain from the url
    //E.g., "https://login.windows.net/omercantest.onmicrosoft.com"
    //will become "https://login.windows.net/*.onmicrosoft.com"
    NSRegularExpression* regex = [NSRegularExpression regularExpressionWithPattern: @"/[^/.]+.onmicrosoft.com"
                                                                           options: NSRegularExpressionCaseInsensitive
                                                                             error: nil];
    
    NSString* scrubbedUrl = [regex stringByReplacingMatchesInString:url
                                                          options:0
                                                            range:NSMakeRange(0, [url length])
                                                     withTemplate:@"/*.onmicrosoft.com"];
    return scrubbedUrl;
}

@end