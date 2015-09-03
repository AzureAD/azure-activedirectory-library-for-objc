//
//  ADTestURLConnection.m
//  ADALiOS
//
//  Created by Ryan Pangrle on 9/2/15.
//  Copyright (c) 2015 MS Open Tech. All rights reserved.
//

#import "ADTestURLConnection.h"

@implementation NSURLConnection (TestConnectionOverride)


- (id)initWithRequest:(NSURLRequest *)request delegate:(id)delegate startImmediately:(BOOL)startImmediately
{
    return (NSURLConnection*)[[ADTestURLConnection alloc] initWithRequest:request delegate:delegate startImmediately:startImmediately];
}

- (id)initWithRequest:(NSURLRequest *)request delegate:(id)delegate
{
    return [self initWithRequest:request delegate:delegate startImmediately:YES];
}

@end

@implementation ADTestURLConnection
{
    NSOperationQueue* _delegateQueue;
    NSURLRequest* _request;
    id _delegate;
}

+ (void)addExpectedRequestResponse:(ADTestRequestResponse*)requestResponse
{
    
}

// If you need to test a series of requests and responses use this API
+ (void)addExpectedRequestsAndResponses:(NSArray*)requestsAndResponses
{
    
}

+ (ADTestRequestResponse*)findResponseForRequestURL:(NSURL*)requestUrl
{
    return nil;
}

- (id)initWithRequest:(NSURLRequest*)request delegate:(id)delegate startImmediately:(BOOL)startImmediately
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _delegate = delegate;
    _request = request;
    
    if (startImmediately)
    {
        [self start];
    }
    
    return self;
}

- (void)setDelegateQueue:(NSOperationQueue*)queue
{
    _delegateQueue = queue;
}

- (void)start
{
    [ADTestURLConnection findResponseForRequestURL:[_request URL]];
}

- (void)cancel
{
    
}

@end
