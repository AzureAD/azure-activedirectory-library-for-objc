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


#import "ADTestURLSession.h"
#import "ADTestURLSessionDataTask.h"
#import "ADTestURLResponse.h"
#import "NSDictionary+ADExtensions.h"
#import "ADOAuth2Constants.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-protocol-method-implementation"
@implementation NSURLSession (TestSessionOverride)

+ (NSURLSession *)sessionWithConfiguration:(NSURLSessionConfiguration *)configuration
                                  delegate:(id)delegate
                             delegateQueue:(NSOperationQueue *)queue
{
    (void)configuration;
    return (NSURLSession *)[[ADTestURLSession alloc] initWithDelegate:delegate delegateQueue:queue];
}

@end
#pragma clang diagnostic pop

@implementation ADTestURLSession

static NSMutableArray* s_responses = nil;

- (id)initWithDelegate:(id)delegate delegateQueue:(NSOperationQueue *)delegateQueue
{
    if (!(self = [super init]))
    {
        return nil;
    }
    self.delegate = delegate;
    self.delegateQueue = delegateQueue;
    
    return self;
}




+ (void)initialize
{
    s_responses = [NSMutableArray new];
}

+ (void)addResponse:(ADTestURLResponse *)response
{
    [s_responses addObject:response];
}

+ (void)addResponses:(NSArray *)responses
{
    if (!responses)
    {
        return;
    }
    NSArray* copy = [responses mutableCopy];
    [s_responses addObject:copy];
}

+ (void)addNotFoundResponseForURLString:(NSString *)URLString
{
    [self addResponse:[ADTestURLResponse serverNotFoundResponseForURLString:URLString]];
}

+ (void)addValidAuthorityResponse:(NSString *)authority
{
    [self addResponse:[ADTestURLResponse responseValidAuthority:authority]];
}

+ (void)addInvalidAuthorityResponse:(NSString *)authority
{
    [self addResponse:[ADTestURLResponse responseInvalidAuthority:authority]];
}

+ (BOOL)noResponsesLeft
{
    return s_responses.count == 0;
}

+ (void)clearResponses
{
    [s_responses removeAllObjects];
}



- (NSURLSessionDataTask *)dataTaskWithURL:(NSURL *)url
{
    NSURLRequest *request = [NSURLRequest requestWithURL:url];
    ADTestURLSessionDataTask *task = [[ADTestURLSessionDataTask alloc] initWithRequest:request delegate:self.delegate session:self];
    
    return (NSURLSessionDataTask *)task;
}

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request
{
    ADTestURLSessionDataTask *task = [[ADTestURLSessionDataTask alloc] initWithRequest:request delegate:self.delegate session:self];
    
    return (NSURLSessionDataTask *)task;
}


+ (ADTestURLResponse *)removeResponseForRequest:(NSURLRequest *)request
{
    NSUInteger cResponses = [s_responses count];
    
    NSURL *requestURL = [request URL];
    
    NSData *body = [request HTTPBody];
    NSDictionary *headers = [request allHTTPHeaderFields];
    
    for (NSUInteger i = 0; i < cResponses; i++)
    {
        id obj = [s_responses objectAtIndex:i];
        ADTestURLResponse *response = nil;
        
        if ([obj isKindOfClass:[ADTestURLResponse class]])
        {
            response = (ADTestURLResponse*)obj;
            
            if ([response matchesURL:requestURL] && [response matchesHeaders:headers] && [response matchesBody:body])
            {
                [s_responses removeObjectAtIndex:i];
                return response;
            }
        }
        
        if ([obj isKindOfClass:[NSMutableArray class]])
        {
            NSMutableArray *subResponses = [s_responses objectAtIndex:i];
            response = [subResponses objectAtIndex:0];
            
            if ([response matchesURL:requestURL] && [response matchesHeaders:headers] && [response matchesBody:body])
            {
                [subResponses removeObjectAtIndex:0];
                if ([subResponses count] == 0)
                {                    [s_responses removeObjectAtIndex:i];
                }
                return response;
            }
        }
    }
    
    return nil;
}

- (void)dispatchIfNeed:(void (^)(void))block
{
    if (_delegateQueue) {
        [_delegateQueue addOperationWithBlock:block];
    }
    else
    {
        block();
    }
}

#pragma mark - NSURLSession
// Runtime methods for NSURLSession, needs to declare since this is a NSObject, not :NSURLSession
// For now though, of no real usage
- (void)set_isSharedSession:(BOOL)shared
{
    (void)shared;
}

- (void)_removeProtocolClassForDefaultSession:(Class)arg1
{
    (void)arg1;
}
- (bool)_prependProtocolClassForDefaultSession:(Class)arg1
{
    (void)arg1;
    return NO;
}

- (void)finishTasksAndInvalidate
{
    self.delegate = nil;
    self.delegateQueue = nil;
}



@end
