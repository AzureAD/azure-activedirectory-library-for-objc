// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import <Foundation/Foundation.h>
#import "ADTokenCacheItem.h"

@class ADAuthenticationError;
@class ADAuthenticationResult;

@interface ADTokenCacheItem (Internal)

- (NSDictionary*)additionalServer;
- (NSMutableDictionary*)additionalClient;

- (void)setAdditionalClient:(NSMutableDictionary*)additionalClient;

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

- (void)logMessage:(NSString *)message
             level:(ADAL_LOG_LEVEL)level
     correlationId:(NSUUID*)correlationId;

/*! Return NO only if the item contains an access token and ext_expires_in in additionalServer has not expired. */
- (BOOL)isExtendedLifetimeExpired;

@end
