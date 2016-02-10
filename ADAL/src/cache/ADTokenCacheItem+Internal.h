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
#import "ADTokenCacheItem.h"

@class ADAuthenticationError;
@class ADAuthenticationResult;

@interface ADTokenCacheItem (Internal)

- (void)checkCorrelationId:(NSDictionary*)response
      requestCorrelationId:(NSUUID*)requestCorrelationId;

- (ADAuthenticationResult *)processTokenResponse:(NSDictionary *)response
                                     fromRefresh:(BOOL)fromRefreshTokenWorkflow
                            requestCorrelationId:(NSUUID*)requestCorrelationId
                                    fieldToCheck:(NSString*)fieldToCheck;

- (ADAuthenticationResult *)processTokenResponse:(NSDictionary *)response
                                     fromRefresh:(BOOL)fromRefreshTokenWorkflow
                            requestCorrelationId:(NSUUID*)requestCorrelationId;

/*!
    Fills out the cache item with the given response dictionary
 
    @return Whether the resulting item is a Multi Resource Refresh Token
 */
- (BOOL)fillItemWithResponse:(NSDictionary*)responseDictionary;

- (void)makeTombstone:(NSDictionary*)tombstoneEntries;

@end
