/*
 Copyright (C) Microsoft. All rights reserved.
 
 Synopsis:  This file adds threading helper functions and macros to use GCD
 
 Owner: SVallur
 Created: 1/9/2013
 */

#import <Foundation/Foundation.h>
#import "CUTDispatch.h"

void CUT_DISPATCH_ASYNC_CONCURRENT_QUEUE_PRIORITY(dispatch_queue_priority_t priority, void (^block)())
{
    dispatch_async(dispatch_get_global_queue(priority, 0), block);
}

void CUT_DISPATCH_ASYNC_CONCURRENT_QUEUE(void (^block)())
{
    CUT_DISPATCH_ASYNC_CONCURRENT_QUEUE_PRIORITY(DISPATCH_QUEUE_PRIORITY_DEFAULT, block);
}

void CUT_DISPATCH_ASYNC_MAIN_QUEUE(void (^block)())
{
    dispatch_async(dispatch_get_main_queue(), block);
}

// If current queue is main queue, execute the block. Otherwise dispatch the block for asynchronous execution on the main queue.
void CUT_DISPATCH_ASYNC_MAIN_QUEUE_IF_NEEDED(void (^block)())
{
    if (![NSThread isMainThread])
    {
        CUT_DISPATCH_ASYNC_MAIN_QUEUE(block);
    }
    else
    {
        block();
    }
}
