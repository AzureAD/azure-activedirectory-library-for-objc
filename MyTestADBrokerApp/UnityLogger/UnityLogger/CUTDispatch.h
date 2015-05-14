/*
 Copyright (C) Microsoft. All rights reserved.
 
 Synopsis:  This file adds threading helper functions and macros to use GCD
 
 Owner: SVallur
 Created: 1/9/2013
 */

// Dispatch block for asynchronous executionon the global concurrent queue specifiying which priority.

#import <Foundation/Foundation.h>
void CUT_DISPATCH_ASYNC_CONCURRENT_QUEUE_PRIORITY(dispatch_queue_priority_t priority, void (^block)());

// Dispatch block for asynchronous execution on the global concurrent default priority queue.
void CUT_DISPATCH_ASYNC_CONCURRENT_QUEUE(void (^block)());

// Dispatch to the main queue
void CUT_DISPATCH_ASYNC_MAIN_QUEUE(void (^block)());

// Dispatch to the main queue if not currently on it.
void CUT_DISPATCH_ASYNC_MAIN_QUEUE_IF_NEEDED(void (^block)());

