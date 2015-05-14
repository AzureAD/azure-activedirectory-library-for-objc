/*
 Copyright (c) Microsoft. All rights reserved.
 
 Synopsis:  Operations for circular files.
 
 Owner:     Yiwei Zhang
 Created:   06/10/2013
 */

#import <Foundation/Foundation.h>

extern NSString *const kCUTCircularFileNameFormat;

@interface CUTCircularFileOperator : NSObject


+(BOOL) isSizeAboveLimitForFile:(NSString *)fileName
                withFileManager:(NSFileManager *)fileManager
                   andSizeLimit:(NSUInteger) maxFileSize;

/**
 @brief Get the data from oldes to latest log files
 @param file manager
 @param path of the file
 @param base name of the file
 @param extension of the file
 @param maximum number of files
 @param error that holds
 @return NSData of crash log
 */
+(NSMutableData *) dataFromCombinedFilesWithFileManager:(NSFileManager *)fileManager
                                    andDirectory:(NSString *) path
                                     andFileName:(NSString *) baseLogFileName
                                andFileExtension:(NSString *) extensionName
                                andMaxFileNumber:(NSUInteger) numberOfLogFiles
                                       withError:(NSError **) error;

/**
 @brief Return the file name needs be opened. Return the latest file or the oldest if the latest is too big
 @param file manager
 @param path of the file
 @param base name of the file
 @param extension of the file
 @param maximum number of files
 @param maximum size limit of the file
 @param should append content to file or not
 @return name of the file
 */
+(NSString *) fileNameToOpenInCircularWithFileManager:(NSFileManager *) fileManager
                                         andDirectory:(NSString *) path
                                          andFileName:(NSString *) baseFileName
                                     andFileExtension:(NSString *) extensionName
                                     andMaxFileNumber:(NSUInteger) maxNumberOfFiles
                                         andSizeLimit:(NSUInteger) sizeLimit
                                         andAppending:(BOOL *) shouldAppend;

@end
