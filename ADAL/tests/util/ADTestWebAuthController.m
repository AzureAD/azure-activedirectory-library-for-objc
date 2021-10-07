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

#import "ADTestWebAuthController.h"
#import "MSIDWebviewAuthorization.h"

#pragma mark -
#pragma mark Overriding ADAuthenticationViewController for the test mock
@implementation ADALWebAuthController (TestWebviewOverride)

+ (void)startWithRequest:(ADALRequestParameters *)requestParams
          promptBehavior:(ADPromptBehavior)promptBehavior
            refreshToken:(NSString*)refreshToken
                 context:(ADALAuthenticationContext *)context
              completion:(MSIDWebviewAuthCompletionHandler)completionHandler
{
    if (ADTestWebAuthController.response)
    {
        completionHandler(ADTestWebAuthController.response, nil);
        return;
    }
    
    completionHandler(nil, ADTestWebAuthController.error);
}

@end

@implementation ADTestWebAuthController

static MSIDWebviewResponse *s_response;
static NSError *s_error;

+ (void)setResponse:(MSIDWebviewResponse *)response
{
    s_response = response;
}

+ (MSIDWebviewResponse *)response
{
    return s_response;
}

+ (void)setError:(NSError *)error
{
    s_error = error;
}

+ (NSError *)error
{
    return s_error;
}

+ (void)reset
{
    s_error = nil;
    s_response = nil;
}

@end
