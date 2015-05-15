/*
 Copyright (c) Microsoft. All rights reserved.
 
 Synopsis: Settings object for the logger components.
 
 Owner: yiweizha
 Created: 10/06/2013
 */

#import <Foundation/Foundation.h>

/**
 @details  Settings object for logger.
 */
@interface CUTLoggerSettings : NSObject 

/** @brief Level mask indicating which tracing levels should be logged */
@property (nonatomic, assign) NSUInteger logLevelMask;

/** @brief Config mask indicating which entities (timestamp, file name, function name, etc) to be logged */
@property (nonatomic, assign) NSUInteger logConfigMask;

@end
