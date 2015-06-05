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

#import <Foundation/Foundation.h>
@class ADBrokerPRTCacheItem;

typedef void(^ADPRTResultCallback)(ADBrokerPRTCacheItem* item, NSError* error);
typedef void(^ADOnResultCallback)(NSError* error);
@interface ADBrokerPRTContext : NSObject

- (id)initWithUpn:(NSString*)upn
        authority:(NSString*)authority
    correlationId:(NSUUID*)correlationId
            error:(ADAuthenticationError* __autoreleasing *) error;

/*! Gets PRT using Broker Token. Assumes that the device was successfully WPJ.*/
- (void)acquirePRTForUPN:(ADPRTResultCallback)callback;


/*! Gets token for a client Id using PRT. If expired, the PRT is refreshed via webview.*/
- (void)acquireTokenUsingPRTForResource:(NSString*) resource
                               clientId:(NSString*) clientId
                            redirectUri:(NSString*) redirectUri
                                 appKey:(NSString*) appKey
                        completionBlock:(ADAuthenticationCallback) completionBlock;


- (void)deletePRT;
@end
