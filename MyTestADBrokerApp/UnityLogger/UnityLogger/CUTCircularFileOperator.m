/*
 Copyright (c) Microsoft. All rights reserved.
 
 Synopsis:  Operations for circular files.
 
 Owner:     Yiwei Zhang
 Created:   06/10/2013
 */

#import "CUTCircularFileOperator.h"

//
//The format of the log file name
//
NSString *const kCUTCircularFileNameFormat = @"%@-%lu.%@";


#pragma mark - CUTCircularFileOperator implementation

@implementation CUTCircularFileOperator

//
// Format the full file path
//
+(NSString *) fileNameWithDirectory:(NSString *) path
                    andBaseFileName:(NSString *) baseFileName
                           andIndex:(NSUInteger) index
                       andExtension:(NSString *) extension
{
    NSString *fileName = nil;
    
    if ((path.length > 0) && (baseFileName.length > 0))
    {
        fileName = [path stringByAppendingPathComponent:
                    [NSString stringWithFormat:kCUTCircularFileNameFormat, baseFileName, (unsigned long)index, extension]];
    }
    
    return fileName;
}

//
// Create a file. If it is already there, createFileAtPath should delete it first
//
+(BOOL) createFileWithName:(NSString *)fileName andFileManager:(NSFileManager *)fileManager
{
    // According to NSFileManager spec, if file is already there, it will be deleted and then a new file is created
    if ([fileManager createFileAtPath:fileName contents:nil attributes:nil])
    {
        return YES;
    }
    else
    {
        printf("Cannot create file %s\n", fileName.UTF8String);
        return NO;
    }
}

//
// Check if current file size reaches limit
//
+(unsigned long long) getCurrentFilesizeInBytes:(NSString *)fileName
                  withFileManager:(NSFileManager *)fileManager {
    // get the file size.
    NSDictionary *fileAttributes = [fileManager attributesOfItemAtPath:fileName error:nil];
    
    // If we cannot get file attributes, assume its size is over limit
    if (fileAttributes == nil)
    {
        printf("Could not get file attributes for %s\n", fileName.UTF8String);
        return 0;
    }
    
    return [fileAttributes fileSize];
}

//
// Check if current file size reaches limit
//
+(BOOL) isSizeAboveLimitForFile:(NSString *)fileName withFileManager:(NSFileManager *)fileManager andSizeLimit:(NSUInteger) maxFileSize
{
    return [CUTCircularFileOperator getCurrentFilesizeInBytes:fileName
                                              withFileManager:fileManager] >= maxFileSize;
}

//
// Find the latest log file and return its index.
// If no log file is created so far, return 0. If error occurs, return -1
//
+(NSInteger) latestFileIndexWithFileManager:(NSFileManager *)fileManager
                               andDirectory:(NSString *) path
                                andFileName:(NSString *) baseFileName
                           andFileExtension:(NSString *) extensionName
                           andMaxFileNumber:(NSUInteger) numberOfFiles
{
    NSDate *latestDate = nil;
    NSString *fileName = nil;
    NSInteger i = 0;
    
    if ((fileManager == nil) || (path.length <= 0) || (baseFileName.length <= 0))
    {
        printf("Invalid input file manager or path\n");
        return -1;
    }
    
    for (i = 0; i < numberOfFiles; i++)
    {
        fileName = [self fileNameWithDirectory:path andBaseFileName:baseFileName andIndex:i andExtension:extensionName];
        
        //File does not exist, then break
        if (![fileManager fileExistsAtPath:fileName])
        {
            break;
        }
        
        // get the modified time of current file.
        NSDictionary *fileAttributes = [fileManager attributesOfItemAtPath:fileName error:nil];
        NSDate *currentDate = [fileAttributes fileModificationDate];
        
        // If current file is older than previous file, break. This means file i is older then file i-1
        if ((latestDate != nil) && ([latestDate laterDate:currentDate] == latestDate))
        {
            break;
        }
        
        latestDate = currentDate;
    }
    
    // When we reach here, it means file i-1 is the latest one
    if (i > 0)
    {
        i = i - 1;
    }
    
    printf("Current file index %ld\n", (long)i);
    
    return i;
}

//
// Get the list of log files, from the oldest to the latest
//
+(NSArray *) fileListFromOldestToLatestWithFileManager:(NSFileManager *)fileManager
                                          andDirectory:(NSString *)path
                                           andFileName:(NSString *)baseFileName
                                      andFileExtension:(NSString *)extensionName
                                      andMaxFileNumber:(NSUInteger) numberOfFiles
{
    NSMutableArray *logFileIndexList = nil;
    
    //
    // First, get the index of the latest log file
    //
    NSInteger latestFileIndex = [self latestFileIndexWithFileManager:fileManager
                                                        andDirectory:path
                                                         andFileName:baseFileName
                                                    andFileExtension:extensionName
                                                    andMaxFileNumber:numberOfFiles];
    
    if (latestFileIndex >= 0)
    {
        NSString *latestFileName = [self fileNameWithDirectory:path andBaseFileName:baseFileName andIndex:latestFileIndex andExtension:extensionName];
        
        // If the latest log file does not exist, return
        if (![fileManager fileExistsAtPath:latestFileName])
        {
            return nil;
        }
        
        // Now the index of the oldest file is (i+1) since the oldest file to the latest file is in circular
        // We need to append the file index from the oldest to the latest
        NSInteger fileIndex = (latestFileIndex + 1) % numberOfFiles;
        logFileIndexList = [[NSMutableArray alloc] init];
        
        while (fileIndex != latestFileIndex)
        {
            NSString *tmpLogName = [self fileNameWithDirectory:path andBaseFileName:baseFileName andIndex:fileIndex andExtension:extensionName];
            
            if ([fileManager fileExistsAtPath:tmpLogName])
            {
                [logFileIndexList addObject:tmpLogName];
            }
            
            fileIndex = (fileIndex+1) % numberOfFiles;
        }
        
        [logFileIndexList addObject:latestFileName];
    }
    
    return logFileIndexList;
}


#pragma mark - Public methods

//
// The file name to be opened in circular
//
+(NSString *) fileNameToOpenInCircularWithFileManager:(NSFileManager *)fileManager
                                         andDirectory:(NSString *) path
                                          andFileName:(NSString *) baseFileName
                                     andFileExtension:(NSString *) extensionName
                                      andMaxFileNumber:(NSUInteger) maxNumberOfFiles
                                         andSizeLimit:(NSUInteger) sizeLimit
                                         andAppending:(BOOL *)shouldAppend

{
    // First, we need to find the index of latest log file
    // If there are no log files, set index to 0. If error occurs, index will be negtive
    NSInteger fileIndex = [self latestFileIndexWithFileManager:fileManager
                                                  andDirectory:path
                                                   andFileName:baseFileName
                                              andFileExtension:extensionName
                                               andMaxFileNumber:maxNumberOfFiles];
    
    // If index is negative, reports error and returns
    if (fileIndex < 0)
    {
        printf("Error when trying to get the latest log file!\n");
        return nil;
    }
    
    if (shouldAppend != nil)
    {
        *shouldAppend = NO;
    }
    
    NSString *fileName = [self fileNameWithDirectory:path andBaseFileName:baseFileName andIndex:fileIndex andExtension:extensionName];
    
    //If the log file exists, we need to check its size
    if ([fileManager fileExistsAtPath:fileName])
    {
        // If the log file is above limit, we need to removes the oldest and create new one
        if ([self isSizeAboveLimitForFile:fileName withFileManager:fileManager andSizeLimit:sizeLimit])
        {
            // Increase file index so to work on next file
            fileIndex = (fileIndex+1) % maxNumberOfFiles;
            
            NSString *tmpFileName = [self fileNameWithDirectory:path andBaseFileName:baseFileName andIndex:fileIndex andExtension:extensionName];
            
            // If we can create a clean file, we will work on it. Otherwise clean the latest log file
            if ([self createFileWithName:tmpFileName andFileManager:fileManager])
            {
                fileName = tmpFileName;
            }
            else
            {
                if (![self createFileWithName:fileName andFileManager:fileManager])
                {
                    printf("Failed to clear latest log file, will append log to it!");
                }
            }
        }
        else
        {
            // Since the file is not above limit, we will append new content
            if (shouldAppend != nil)
            {
                *shouldAppend = YES;
            }
        }
    }
    else
    {
        [self createFileWithName:fileName andFileManager:fileManager];
    }
    
    return fileName;
}


//
// Combine the data within all the log files, from oldest to latest
//
+(NSMutableData *) dataFromCombinedFilesWithFileManager:(NSFileManager *)fileManager
                                           andDirectory:(NSString *)path
                                            andFileName:(NSString *)baseFileName
                                       andFileExtension:(NSString *)extensionName
                                        andMaxFileNumber:(NSUInteger)numberOfFiles
                                               withError:(NSError **)error
{
    NSMutableData *logData = nil;
    
    if (!error)
    {
        return nil;
    }
    
    // Get the index list of log files, from the oldest to the latest
    NSArray *fileList = [[self class] fileListFromOldestToLatestWithFileManager:fileManager
                                                                   andDirectory:path
                                                                    andFileName:baseFileName
                                                               andFileExtension:extensionName
                                                                andMaxFileNumber:numberOfFiles];
    NSFileHandle *fileHandle = nil;
    
    if (fileList.count > 0)
    {
        logData = [[NSMutableData alloc] init];
        
        //
        // Append the log data from the oldest file to the latest
        //
        for (NSString *fileName in fileList)
        {
            fileHandle = [NSFileHandle fileHandleForReadingAtPath:fileName];
            
            [logData appendData:[fileHandle readDataToEndOfFile]];
        }
    }
    else
    {
        *error = [NSError errorWithDomain:kCUTLoggerDomain code:CUTLoggerErrorFileNotFound userInfo:nil];
    }
    
    return logData;
}

@end
