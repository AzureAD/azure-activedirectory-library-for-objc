/*
 Copyright (c) Microsoft. All rights reserved.
 
 Synopsis:  Logger that writes trace info to plain text file
 
 Owner:     Yiwei Zhang
 Created:   10/06/2013
 */

#import <Foundation/Foundation.h>
#import "CUTLogWriter.h"
#import "CUTCircularFileLogWriterSettings.h"

/**
 @details A log writer that writes log to a plain text
 */
@interface CUTFileLogWriter : NSObject<CUTLogWriter>

/**
 @brief  Create the file logger instance with settings
 @param  File log writer settings
 @return file logger instance
 */
- (id)initWithSettings:(CUTCircularFileLogWriterSettings *) fileLogWriterSettings;

@end
