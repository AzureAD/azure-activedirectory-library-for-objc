// Created by Boris Vidolov on 1/14/14.
// Copyright © Microsoft Open Technologies, Inc.
//
// All Rights Reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
// ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
// PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
//
// See the Apache License, Version 2.0 for the specific language
// governing permissions and limitations under the License.
#import "ADEncryptedFileTokenCacheStore.h"
#import "NSString+ADHelperMethods.h"
#import "ADDefaultTokenCacheStorePersistance.h"

static const uint64_t MAX_REVISION;

const int16_t UPPER_VERSION = 1;
const int16_t LOWER_VERSION = 0;

@implementation ADEncryptedFileTokenCacheStore

-(id) initWithLocation:(NSString *)cacheLocation
{
    if (self = [super initWithLocation:cacheLocation])
    {
        BOOL hasPath = [cacheLocation containsString:@"/"];
        if (!hasPath)
        {
            NSArray  *paths = NSSearchPathForDirectoriesInDomains( NSCachesDirectory, NSUserDomainMask, YES );
            if (paths.count < 1)
            {
                AD_LOG_WARN(@"Token cache file error", @"The caches directory cannot be obtained");
            }
            else
            {
                mCacheLocation = [[paths objectAtIndex:0] stringByAppendingPathComponent:self.cacheLocation];
            }
        }
        //Check if the file exists and loads its contents if yes:
        NSString* logMessage = [NSString stringWithFormat:@"File: %@", self.cacheLocation];
        BOOL isDirectory = NO;
        NSFileManager* fileManager = [NSFileManager defaultManager];
        BOOL present = [fileManager fileExistsAtPath:self.cacheLocation isDirectory:&isDirectory];
        if (present)
        {
            if (isDirectory)
            {
                AD_LOG_INFO(@"Directory specified instead of file.", logMessage);
                return nil;
            }
            
            if ([self addInitialCacheItems])
            {
                AD_LOG_INFO(@"Successfully loaded the cache.", logMessage);
            }
        }
        else
        {
            AD_LOG_INFO(@"No persisted cache found.", logMessage);
            //Create an empty file to ensure that the encryption attribute is set:
            [self persistWithItems:[NSArray new] error:nil];
        }
    }
    return self;
}

//Overrides parent class to perform the actual storage
-(BOOL) persistWithItems: (NSArray*) flatItemsList
                   error: (ADAuthenticationError *__autoreleasing *) error
{
    ADDefaultTokenCacheStorePersistance* serialization =
        [[ADDefaultTokenCacheStorePersistance alloc] initWithUpperVersion:UPPER_VERSION
                                                             lowerVersion:LOWER_VERSION
                                                               cacheItems:flatItemsList];
    BOOL succeeded = [NSKeyedArchiver archiveRootObject:serialization toFile:self.cacheLocation];
    if (succeeded)
    {
        //Always ensure that the file is encrypted after saving:
        NSError* encryptionError;
        [[NSFileManager defaultManager] setAttributes:@{NSFileProtectionKey:NSFileProtectionComplete} ofItemAtPath:self.cacheLocation error:&encryptionError];
        if (encryptionError)
        {
            NSString* details = [NSString stringWithFormat:@"Unable to set encryption on the token cache store file: %@", encryptionError.description];
            ADAuthenticationError* adError = [ADAuthenticationError errorFromNSError:encryptionError errorDetails:details];
            if (error)
            {
                *error = adError;
            }
        }
    }
    else
    {
        NSString* errorMessage = [NSString stringWithFormat:@"Failed to persist to file: %@", self.cacheLocation];
        //Note that this will also log the error:
        ADAuthenticationError* toReport = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_CACHE_PERSISTENCE
                                                                                 protocolCode:nil
                                                                                 errorDetails:errorMessage];
        if (error)
        {
            *error = toReport;
        }
    }
    
    return succeeded;
}

//Overrides the parent class
-(NSArray*) unpersist
{
    ADDefaultTokenCacheStorePersistance* serialization = [NSKeyedUnarchiver unarchiveObjectWithFile:self.cacheLocation];
    if (!serialization || ![serialization isKindOfClass:[ADDefaultTokenCacheStorePersistance class]])
    {
        //The userId should be valid:
        NSString* message = [NSString stringWithFormat:@"Cannot read the file: %@", self.cacheLocation];
        //This will also log the error:
        [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_BAD_CACHE_FORMAT protocolCode:nil errorDetails:message];
        return nil;
    }
    
    if (serialization->upperVersion > UPPER_VERSION)
    {
        //A new, incompatible version of the cache is stored, ignore the cache:
        //The userId should be valid:
        NSString* message = [NSString stringWithFormat:@"The version (%d.%d) of the cache file is not supported. File: %@",
                             serialization->upperVersion, serialization->lowerVersion, self.cacheLocation];
        //This will also log the error:
        [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_BAD_CACHE_FORMAT protocolCode:nil errorDetails:message];
        return nil;
    }
    else
    {
        AD_LOG_VERBOSE_F(@"Token Cache Store Persistence", @"Finished reading of the persisted cache. Version: (%d.%d);  File: %@",
                         serialization->upperVersion, serialization->lowerVersion, self.cacheLocation);
    }
    return serialization->cacheItems;
}

@end
