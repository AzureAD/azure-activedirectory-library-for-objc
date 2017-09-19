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

#include <assert.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/sysctl.h>

// From https://developer.apple.com/library/content/qa/qa1361/_index.html
static bool AmIBeingDebugged(void)
// Returns true if the current process is being debugged (either
// running under the debugger or has a debugger attached post facto).
{
    int                 junk;
    int                 mib[4];
    struct kinfo_proc   info;
    size_t              size;
    
    // Initialize the flags so that, if sysctl fails for some bizarre
    // reason, we get a predictable result.
    
    info.kp_proc.p_flag = 0;
    
    // Initialize mib, which tells sysctl the info we want, in this case
    // we're looking for information about a specific process ID.
    
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();
    
    // Call sysctl.
    
    size = sizeof(info);
    junk = sysctl(mib, sizeof(mib) / sizeof(*mib), &info, &size, NULL, 0);
    assert(junk == 0);
    
    // We're being debugged if the P_TRACED flag is set.
    
    return ( (info.kp_proc.p_flag & P_TRACED) != 0 );
}

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
    if (!response)
    {
        return;
    }
    
    @synchronized (self)
    {
        [s_responses addObject:response];
    }
}

+ (void)addResponses:(NSArray *)responses
{
    if (!responses)
    {
        return;
    }
    NSArray* copy = [responses mutableCopy];
    @synchronized (self)
    {
        [s_responses addObject:copy];
    }
}

+ (void)addNotFoundResponseForURLString:(NSString *)URLString
{
    [self addResponse:[ADTestURLResponse serverNotFoundResponseForURLString:URLString]];
}

+ (BOOL)noResponsesLeft
{
    @synchronized (self)
    {
        return s_responses.count == 0;
    }
}

+ (void)clearResponses
{
    @synchronized (self)
    {
        [s_responses removeAllObjects];
    }
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
    NSURL *requestURL = [request URL];
    
    NSData *body = [request HTTPBody];
    NSDictionary *headers = [request allHTTPHeaderFields];
    
    @synchronized (self)
    {
        NSUInteger cResponses = [s_responses count];
        for (NSUInteger i = 0; i < cResponses; i++)
        {
            id obj = [s_responses objectAtIndex:i];
            ADTestURLResponse *response = nil;
            
            if ([obj isKindOfClass:[ADTestURLResponse class]])
            {
                response = (ADTestURLResponse *)obj;
                
                // We don't want the compiler to short circuit this case as finding out in one go all
                // of the data that doesn't match can speed up debugging & fixing tests
                bool match = [response matchesURL:requestURL];
                match &= [response matchesBody:body];
                match &= [response matchesHeaders:headers];
                
                if (match)
                {
                    [s_responses removeObjectAtIndex:i];
                    return response;
                }
            }
            
            if ([obj isKindOfClass:[NSMutableArray class]])
            {
                NSMutableArray *subResponses = [s_responses objectAtIndex:i];
                response = [subResponses objectAtIndex:0];
                
                bool match = [response matchesURL:requestURL];
                match &= [response matchesBody:body];
                match &= [response matchesHeaders:headers];
                
                if (match)
                {
                    [subResponses removeObjectAtIndex:0];
                    if ([subResponses count] == 0)
                    {
                        [s_responses removeObjectAtIndex:i];
                    }
                    return response;
                }
            }
        }
    
        // This class is used in the test target only. If you're seeing this outside the test target that means you linked in the file wrong
        // take it out!
        //
        // No unit tests are allowed to hit network. This is done to ensure reliability of the test code. Tests should run quickly and
        // deterministically. If you're hitting this assert that means you need to add an expected request and response to ADTestURLConnection
        // using the ADTestRequestReponse class and add it using -[ADTestURLConnection addExpectedRequestResponse:] if you have a single
        // request/response or -[ADTestURLConnection addExpectedRequestsAndResponses:] if you have a series of network requests that you need
        // to ensure happen in the proper order.
        //
        // Example:
        //
        // MSALTestRequestResponse *response = [MSALTestRequestResponse requestURLString:@"https://requestURL"
        //                                                             responseURLString:@"https://idontknowwhatthisshouldbe.com"
        //                                                                  responseCode:400
        //                                                              httpHeaderFields:@{}
        //                                                              dictionaryAsJSON:@{@"tenant_discovery_endpoint" : @"totally valid!"}];
        //
        //  [MSALTestURLSession addResponse:response];
        
        if (AmIBeingDebugged())
        {
            NSLog(@"Failed to find repsonse for %@\ncurrent responses: %@", requestURL, s_responses);
            
            // This will cause the tests to immediately stop execution right here if we're in the debugger,
            // hopefully making it a little easier to see why a test is failing. :)
            __builtin_trap();
        }
        
        NSAssert(nil, @"did not find a matching response for %@", requestURL.absoluteString);
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
