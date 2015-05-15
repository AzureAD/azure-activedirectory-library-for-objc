/*
 Copyright © 2012 Microsoft. All rights reserved.
 
 Synopsis: A wrapper for NSFileManager.
 
 Owner: Izik Lisbon
 Created: 02/20/2013
 */

#import "CUTFileManagerImp.h"
#import "CUTError.h"

/**
 @details A wrapper for NSFileManager.
 */
@implementation CUTFileManagerImp
{
    NSFileManager *_fileManager;
    NSString *_appSupportFolderPath;
}

//
// init
//
-(id)init
{
    if ( !(self = [super init]) ) return nil;
    
    _fileManager = [NSFileManager defaultManager];
    
    return self;
}

- (NSString *)appSupportFolderPath
{
    if (_appSupportFolderPath == nil)
    {
        NSArray *directories = NSSearchPathForDirectoriesInDomains(
                                                                   NSApplicationSupportDirectory, // directory
                                                                   NSUserDomainMask, // domain mask
                                                                   YES // expand tilde
                                                                   );
        
        CUTAssertAndReturnValueIfFalse(directories.count == 1u, nil, kCUTUtilityDomain, @"Returned %lu directories, expected 1", (unsigned long)directories.count);
        
        NSString *appSupportPath = [directories lastObject];
        NSString *appSupportPathWithBundleId = [appSupportPath stringByAppendingPathComponent:[[NSBundle mainBundle] bundleIdentifier]];
        
        _appSupportFolderPath = appSupportPathWithBundleId;
    }
    
    return _appSupportFolderPath;
}

//
// fileExistsAtPath:
//
- (BOOL)fileExistsAtPath:(NSString *)path
{
    return [_fileManager fileExistsAtPath:path];
}

//
// attributesOfItemAtPath:error:
//
- (NSDictionary *)attributesOfItemAtPath:(NSString *)path error:(NSError **)error
{
    return [_fileManager attributesOfItemAtPath:path error:error];
}

//
// fileSizeInBytes:error
//
-(NSUInteger)fileSizeInBytes:(NSString*)filePath error:(NSError **)err
{
    // get file's attributes
    NSDictionary *fileAttributes = [self attributesOfItemAtPath:filePath error:err];
    
    // get the size attribute as NSNumber
    NSNumber *fileSizeNumber = [fileAttributes objectForKey:NSFileSize];
    
    // by using unsignedIntegerValue we assume that the file size is less then 4GB
    // but that a legitimate assumption on iOS.
    NSUInteger fileSize = [fileSizeNumber unsignedIntegerValue];
    
    return fileSize;
}

//
// filePathInTempForFilename
//
- (NSString *)filePathInTempForFilename:(NSString *)filename
{
    return [NSTemporaryDirectory() stringByAppendingPathComponent:filename];
}

//
// stringContentAtFile:encoding:error:
//
- (NSDictionary *) dictionaryContentAtFile:(NSString *)path
                                     error:(NSError **)error
{
    if (error)
    {
        *error = nil;
    }
    
    if (!path)
    {
        NSString *errorString = @"path was nil. Cannot read user context.";
        CUTTrace(CUTTraceLevelWarning, kCUTUtilityDomain, @"%@", errorString);
        
        if (error)
        {
            *error = [NSError errorWithDomain:kCUTUtilityDomain code:CUTErrorObjectIsNil message:errorString];
        }
        
        return nil;
    }
    
    CUTTrace(CUTTraceLevelVerbose, kCUTUtilityDomain, @"Reading content from file %@.", path);
    return [[NSDictionary alloc] initWithContentsOfFile:path];
}

//
// writeStringContent:ToFile:atomically:error:
//
- (NSError *)writeDictionaryContent:(NSDictionary *)content
                        ToFile:(NSString *)path
                    atomically:(BOOL)useAuxiliaryFile
{
    return [self writeDictionaryContent:content ToFile:path shouldExcludeFromBackup:NO atomically:useAuxiliaryFile];
}

//
// writeStringContent:ToFile:excludedFromBackup:atomically:
//
- (NSError *)writeDictionaryContent:(NSDictionary *)content
                             ToFile:(NSString *)path
            shouldExcludeFromBackup:(BOOL)excludeFromBackup
                         atomically:(BOOL)useAuxiliaryFile
{
    if (!path)
    {
        NSString *errorString = @"path was nil. Cannot save user context.";
        CUTTrace(CUTTraceLevelWarning, kCUTUtilityDomain, @"%@", errorString);
        
        return [NSError errorWithDomain:kCUTUtilityDomain code:CUTErrorObjectIsNil message:errorString];
    }
    
    NSString *stringContent = [content description];

    NSError *writeToFileError = nil;
    NSError *setExcludeFromBackupError = nil;
    BOOL successWritingToFile = [stringContent writeToFile:path atomically:useAuxiliaryFile encoding:NSUTF8StringEncoding error:&writeToFileError];
    
    // check if we have successfully written the file but requested to exclude from backup
    if (successWritingToFile && excludeFromBackup)
    {
        NSURL *fileUrl = [NSURL fileURLWithPath:path isDirectory:NO];
        BOOL successSettingExcludeFromBackup = [fileUrl setResourceValues:@{NSURLIsExcludedFromBackupKey: @YES}
                             error:&setExcludeFromBackupError];
        
        // if we were not able to exculde from backup, delete the file and fail the operation
        if (!successSettingExcludeFromBackup || setExcludeFromBackupError)
        {
            CUTTraceError(CUTTraceLevelWarning, kCUTUtilityDomain, setExcludeFromBackupError, @"Could not set \"excluded from backup\" property for %@, deleting file.", path);
            
            NSError *deleteFileError = [self deleteFile:path];
            if (deleteFileError)
            {
                CUTTraceError(CUTTraceLevelError, kCUTUtilityDomain, deleteFileError, @"Could not delete file after failure to exclude from backup; file: %@", path);
            }
        }
    }
    
    return writeToFileError != nil ? writeToFileError : setExcludeFromBackupError;
}

//
// deleteFile:
//
- (NSError *)deleteFile:(NSString *)path
{
    if (!path)
    {
        NSString *errorString = @"path was nil. Cannot delete user context.";
        CUTTrace(CUTTraceLevelWarning, kCUTUtilityDomain, @"%@", errorString);
        
        return [NSError errorWithDomain:kCUTUtilityDomain code:CUTErrorObjectIsNil message:errorString];
    }
    
    NSError *error = nil;
    
    CUTTrace(CUTTraceLevelVerbose, kCUTUtilityDomain, @"Deleting file %@.", path);
    [_fileManager removeItemAtPath:path error:&error];
    
    return error;
}

//
// createFileAtPath: contents: attributes:
//
- (BOOL)createFileAtPath:(NSString *)path contents:(NSData *)data attributes:(NSDictionary *)attr
{
    return [_fileManager createFileAtPath:path contents:data attributes:attr];
}

//
// createDirectoryAtPath:withIntermediateDirectories:attributes:error:
//
- (BOOL)createDirectoryAtPath:(NSString *)path
  withIntermediateDirectories:(BOOL)createIntermediateDirectories
                   attributes:(NSDictionary *)attributes
                        error:(NSError *__autoreleasing *)error
{
    CUTTrace(CUTTraceLevelVerbose, kCUTUtilityDomain, @"Creating directory at path: \"%@\"", path);
    
    if (error)
    {
        *error = nil;
    }
    
    if (!path)
    {
        CUTTrace(CUTTraceLevelWarning, kCUTUtilityDomain, @"Cannot create directory with nil path");
        
        if (error)
        {
            *error = [NSError errorWithDomain:kCUTUtilityDomain
                                         code:CUTErrorObjectIsNil
                                      message:@"Cannot create directory with nil path"];
        }
        
        return NO;
    }
    
    return [_fileManager createDirectoryAtPath:path
                   withIntermediateDirectories:createIntermediateDirectories
                                    attributes:attributes
                                         error:error];
}

@end
