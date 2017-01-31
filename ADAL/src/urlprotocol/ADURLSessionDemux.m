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

#import "ADURLSessionDemux.h"
#import <objc/runtime.h>

@interface ADURLSessionDemuxTaskInfo : NSObject

- (instancetype)initWithTask:(NSURLSessionDataTask *)task delegate:(id<NSURLSessionDataDelegate>)delegate;

@property (atomic, strong) NSURLSessionDataTask *task;
@property (atomic, strong) id<NSURLSessionDataDelegate> delegate;
@property (atomic, strong) NSThread *thread;

- (void)performBlock:(dispatch_block_t)block;

- (void)invalidate;

@end

@implementation ADURLSessionDemuxTaskInfo

- (instancetype)initWithTask:(NSURLSessionDataTask *)task delegate:(id<NSURLSessionDataDelegate>)delegate
{
    self = [super init];
    if (self != nil)
    {
        self->_task = task;
        self->_delegate = delegate;
        self->_thread = [NSThread currentThread];
    }
    return self;
}

- (void)performBlock:(dispatch_block_t)block
{
    [self performSelector:@selector(performBlockOnClientThread:)
                 onThread:self.thread
               withObject:[block copy]
            waitUntilDone:NO];
}

- (void)performBlockOnClientThread:(dispatch_block_t)block
{
    block();
}

- (void)invalidate
{
    self.delegate = nil;
    self.thread = nil;
}

@end


@interface ADURLSessionDemux() <NSURLSessionDataDelegate>

@end


@implementation ADURLSessionDemux

static const void *taskKey = &taskKey;

- (instancetype)initWithConfiguration:(NSURLSessionConfiguration *)configuration
                        delegateQueue:(NSOperationQueue *)delegateQueue
{
    self = [super init];
    if (self)
    {
        self->_configuration = [configuration copy];
        self->_session = [NSURLSession sessionWithConfiguration:self->_configuration delegate:self delegateQueue:delegateQueue];
    }
    
    return self;
}

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request delegate:(id<NSURLSessionDataDelegate>)delegate
{
    NSURLSessionDataTask *task;
    ADURLSessionDemuxTaskInfo *taskInfo;
    
    task = [self.session dataTaskWithRequest:request];
    taskInfo = [[ADURLSessionDemuxTaskInfo alloc] initWithTask:task
                                                      delegate:delegate];
    
    objc_setAssociatedObject(task, taskKey, taskInfo, OBJC_ASSOCIATION_RETAIN);
    
    return task;
}

- (ADURLSessionDemuxTaskInfo *)taskInfoForTask:(NSURLSessionTask *)task
{
    ADURLSessionDemuxTaskInfo *result;
    result = objc_getAssociatedObject(task, taskKey);
    return result;
}

#pragma mark - NSURLSession delegates

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
willPerformHTTPRedirection:(NSHTTPURLResponse *)response
        newRequest:(NSURLRequest *)newRequest
 completionHandler:(void (^)(NSURLRequest *))completionHandler
{
    ADURLSessionDemuxTaskInfo *taskInfo;
    
    taskInfo = [self taskInfoForTask:task];
    if ([taskInfo.delegate respondsToSelector:@selector(URLSession:task:willPerformHTTPRedirection:newRequest:completionHandler:)])
    {
        [taskInfo performBlock:^{
            [taskInfo.delegate URLSession:session task:task willPerformHTTPRedirection:response newRequest:newRequest completionHandler:completionHandler];
        }];
    }
    else
    {
        completionHandler(newRequest);
    }
}

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential))completionHandler
{
    ADURLSessionDemuxTaskInfo *taskInfo;
    
    taskInfo = [self taskInfoForTask:task];
    if ([taskInfo.delegate respondsToSelector:@selector(URLSession:task:didReceiveChallenge:completionHandler:)])
    {
        [taskInfo performBlock:^{
            [taskInfo.delegate URLSession:session task:task didReceiveChallenge:challenge completionHandler:completionHandler];
        }];
    }
    else
    {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
    }
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error
{
    ADURLSessionDemuxTaskInfo *taskInfo;
    
    taskInfo = [self taskInfoForTask:task];
    
    if ([taskInfo.delegate respondsToSelector:@selector(URLSession:task:didCompleteWithError:)])
    {
        [taskInfo performBlock:^{
            [taskInfo.delegate URLSession:session task:task didCompleteWithError:error];
            [taskInfo invalidate];
        }];
    }
    else
    {
        [taskInfo invalidate];
    }
}

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)dataTask
didReceiveResponse:(NSURLResponse *)response
 completionHandler:(void (^)(NSURLSessionResponseDisposition disposition))completionHandler
{
    ADURLSessionDemuxTaskInfo *    taskInfo;
    
    taskInfo = [self taskInfoForTask:dataTask];
    if ([taskInfo.delegate respondsToSelector:@selector(URLSession:dataTask:didReceiveResponse:completionHandler:)])
    {
        [taskInfo performBlock:^{
            [taskInfo.delegate URLSession:session dataTask:dataTask didReceiveResponse:response completionHandler:completionHandler];
        }];
    }
    else
    {
        completionHandler(NSURLSessionResponseAllow);
    }
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data
{
    ADURLSessionDemuxTaskInfo *    taskInfo;
    
    taskInfo = [self taskInfoForTask:dataTask];
    if ([taskInfo.delegate respondsToSelector:@selector(URLSession:dataTask:didReceiveData:)])
    {
        [taskInfo performBlock:^{
            [taskInfo.delegate URLSession:session dataTask:dataTask didReceiveData:data];
        }];
    }
}


@end
