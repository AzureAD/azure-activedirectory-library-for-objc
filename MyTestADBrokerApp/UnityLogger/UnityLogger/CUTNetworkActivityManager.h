/*
 Copyright (c) Microsoft. All rights reserved.
 
 Synopsis: Manager for network activity related operations.
 
 Owner: NicholC
 Created: 11/21/2013
 */

#import <Foundation/Foundation.h>

/**
 @details Manager for network activity related operations.
 */
@interface CUTNetworkActivityManager : NSObject

/**
 @brief Returns the singleton shared manager. On first access, it will create the singleton instance.
 @return The singleton shared manager.
 */
+ (CUTNetworkActivityManager *)sharedManager;

/**
 @brief Change the current activity state. For each call to change the activity state to be in progress, there should be a corresponding call to make in not in progress when the activity completes.
 @param isInProgress YES if the network is being used, NO otherwise.
 */
- (void)setActivityInProgress:(BOOL)isInProgress;

@end
