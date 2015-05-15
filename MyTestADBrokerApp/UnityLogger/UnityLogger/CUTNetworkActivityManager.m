/*
 Copyright (c) Microsoft. All rights reserved.
 
 Synopsis: Manager for network activity related operations.
 
 Owner: NicholC
 Created: 11/21/2013
 */

#import "CUTNetworkActivityManager.h"
#import "CUTDispatch.h"
#import <UIKit/UIKit.h>

#pragma mark - CUTNetworkActivityManager (extension)

@interface CUTNetworkActivityManager ()

// Number of activities in progress. Used to keep track of whether or not the activity indicator should be visible.
@property (nonatomic, assign) NSUInteger activityInProgressCount;

@end

#pragma mark - CUTNetworkActivityManager (implementation)

@implementation CUTNetworkActivityManager

//
// sharedManager
//
+ (CUTNetworkActivityManager *)sharedManager
{
    static CUTNetworkActivityManager *sharedInstance = nil;
    
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedInstance = [[CUTNetworkActivityManager alloc] init];
    });
    
    return sharedInstance;
}

//
// setActivityInProgress:
//
- (void)setActivityInProgress:(BOOL)isInProgress
{
    @synchronized(self)
    {
        if (!isInProgress && self.activityInProgressCount == 0)
        {
            // No-op. Don't decrement because there will be underflow.
            return;
        }
        
        self.activityInProgressCount += (isInProgress) ? 1 : -1;
        
        // NOTE: Don't pass a pointer to self to the main queue. This will ruin
        // the thread safety.
        BOOL shouldIndicatorBeVisible = (self.activityInProgressCount > 0);
        CUT_DISPATCH_ASYNC_MAIN_QUEUE_IF_NEEDED(^{
            [UIApplication sharedApplication].networkActivityIndicatorVisible = shouldIndicatorBeVisible;
        });
    }
}

@end
