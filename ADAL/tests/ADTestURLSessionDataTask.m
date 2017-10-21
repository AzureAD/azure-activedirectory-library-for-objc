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


#import "ADTestURLSessionDataTask.h"
#import "ADTestURLSession.h"
#import "ADTestURLResponse.h"

@interface ADTestURLSessionDataTask()

@property (nonatomic, weak) id delegate;
@property (nonatomic, weak) ADTestURLSession *session;
@property (nonatomic, strong) NSURLRequest *request;

@end

@implementation ADTestURLSessionDataTask

- (id)initWithRequest:(NSURLRequest *)request
             delegate:(id)delegate
              session:(ADTestURLSession *)session
{
    self = [super init];
    if (self)
    {
        self.delegate = delegate;
        self.session = session;
        self.request = request;
    }
    return self;
}


- (void)resume
{
    ADTestURLResponse *response = [ADTestURLSession removeResponseForRequest:self.request];
    
    if (!response)
    {
        [self.session dispatchIfNeed:^{
            NSError* error = [NSError errorWithDomain:NSURLErrorDomain
                                                 code:NSURLErrorNotConnectedToInternet
                                             userInfo:nil];
            [self.delegate URLSession:(NSURLSession *)self.session
                                 task:(NSURLSessionDataTask *)self
                 didCompleteWithError:error];
        }];
        
        return;
    }
    
    if (response->_waitSemaphore)
    {
        dispatch_semaphore_wait(response->_waitSemaphore, DISPATCH_TIME_FOREVER);
    }
    
    if (response->_error)
    {
        [self.session dispatchIfNeed:^{
            [self.delegate URLSession:(NSURLSession *)self.session
                                 task:(NSURLSessionDataTask *)self
                 didCompleteWithError:response->_error];
        }];
        return;
    }
    if (response->_expectedRequestHeaders)
    {
        BOOL failed = NO;
        for (NSString *key in response->_expectedRequestHeaders)
        {
            NSString *value = [response->_expectedRequestHeaders objectForKey:key];
            NSString *requestValue = [_request.allHTTPHeaderFields objectForKey:key];
            
            if (!requestValue)
            {
                AD_LOG_ERROR(AD_FAILED, nil, nil, NO, @"Missing request header, expected \"%@\" header", key);
                failed = YES;
            }
            
            if (![requestValue isEqualToString:value])
            {
                AD_LOG_ERROR(AD_FAILED, nil, nil, NO, @"Mismatched request header. On \"%@\" header, expected:\"%@\" actual:\"%@\"", key, value, requestValue);
                failed = YES;
            }
        }
        
        if (failed)
        {
            [self.session dispatchIfNeed:^{
                [self.delegate URLSession:(NSURLSession *)self.session
                                     task:(NSURLSessionDataTask *)self
                     didCompleteWithError:[NSError errorWithDomain:NSURLErrorDomain
                                                              code:NSURLErrorNotConnectedToInternet
                                                          userInfo:nil]];
            }];
            return;
        }
    }

    
    if (response->_response)
    {
        [self.session dispatchIfNeed:^{
            [self.delegate URLSession:(NSURLSession *)self.session
                             dataTask:(NSURLSessionDataTask *)self
                   didReceiveResponse:response->_response
                    completionHandler:^(NSURLSessionResponseDisposition disposition) {
                        (void)disposition;
                    }];
        }];
        
    }
    
    if (response->_responseData)
    {
        [self.session dispatchIfNeed:^{
            [self.delegate URLSession:(NSURLSession *)self.session dataTask:(NSURLSessionDataTask *)self didReceiveData:response->_responseData];
        }];
    }
    
    [self.session dispatchIfNeed:^{
        [self.delegate URLSession:(NSURLSession *)self.session
                             task:(NSURLSessionDataTask *)self
             didCompleteWithError:nil];
    }];
}

@end
