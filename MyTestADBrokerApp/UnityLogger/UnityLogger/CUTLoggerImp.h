/*
 Copyright © Microsoft. All rights reserved.
 
 Synopsis:  Class implementation of CUTLogger.
 
 Owner: yiweizha
 Created: 10/06/2013
 */

#import <Foundation/Foundation.h>
#import "CUTLoggerSettings.h"
#import "CUTLogger.h"

/**
 @details CUTLoggerImp will accept logging request and notify its delegates to do the logging.
 */
@interface CUTLoggerImp : NSObject<CUTLogger>

/**
 @brief  Create the logger instance with logger settings
 @param  Logger settings
 @return logger instance
 */
- (id)initWithLoggerSettings:(CUTLoggerSettings *) loggerSettings;

@end 
