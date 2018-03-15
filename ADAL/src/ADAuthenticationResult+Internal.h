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

#import "ADAuthenticationResult.h"

@class ADTokenCacheItem;
@class MSIDBrokerResponse;

/* Internally accessible methods.*/
@interface ADAuthenticationResult (Internal)

/*! Creates a result from a user or request cancellation condition, with/without correlation id. */
+ (ADAuthenticationResult*)resultFromCancellation;
+ (ADAuthenticationResult*)resultFromCancellation:(NSUUID*)correlationId;

/*! Creates an authentication result from an error condition, with/without correlation id. */
+ (ADAuthenticationResult*)resultFromError:(ADAuthenticationError*)error;
+ (ADAuthenticationResult*)resultFromError:(ADAuthenticationError*)error
                             correlationId:(NSUUID*)correlationId;

/*! Creates an authentication result from an error condition, with/without correlation id. */
+ (ADAuthenticationResult*)resultFromMSIDError:(NSError *)error;
+ (ADAuthenticationResult*)resultFromMSIDError:(NSError *)error
                                 correlationId:(NSUUID *)correlationId;

+ (ADAuthenticationResult*)resultFromParameterError:(NSString*)details;
+ (ADAuthenticationResult*)resultFromParameterError:(NSString*)details
                                      correlationId:(NSUUID*)correlationId;

/*! Creates an instance of the result from a pre-setup token cache store item */
+ (ADAuthenticationResult*)resultFromTokenCacheItem:(ADTokenCacheItem*)item
                               multiResourceRefreshToken:(BOOL)multiResourceRefreshToken
                                           correlationId:(NSUUID*)correlationId;

/*! Creates an authentication result from broker response, which can be with/without correlation id. */
+ (ADAuthenticationResult*)resultFromBrokerResponse:(MSIDBrokerResponse *)response;

/*! Internal method to set the extendedLifetimeToken flag. */
- (void)setExtendedLifeTimeToken:(BOOL)extendedLifeTimeToken;
- (void)setCloudAuthority:(NSString *)cloudAuthority;

@end
