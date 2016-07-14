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

@class ADTokenCacheItem;
@class ADAuthenticationError;

typedef enum
{
    /*! Everything went ok. The result object can be used directly. */
    AD_SUCCEEDED,
    
    /*! User cancelled the action to supply credentials. */
    AD_USER_CANCELLED,
    
    /*! Some error occurred. See the "error" field for details.*/
    AD_FAILED,
    
} ADAuthenticationResultStatus;

/*!
 Represent the authentication result pass to the asynchronous handlers of any operation.
 */
@interface ADAuthenticationResult : NSObject
{
@protected
    //See the corresponding properties for details.
    ADTokenCacheItem*          _tokenCacheItem;
    ADAuthenticationResultStatus    _status;
    ADAuthenticationError*          _error;
    NSUUID*                         _correlationId;
    BOOL                            _multiResourceRefreshToken;
    BOOL                            _extendedLifeTimeToken;
}

/*! See the ADAuthenticationResultStatus details */
@property (readonly) ADAuthenticationResultStatus status;

/*! A valid access token, if the results indicates success. The property is 
 calculated from the tokenCacheItem one. The property is nil, in 
 case of error.*/
@property (readonly) NSString* accessToken;

@property (readonly) ADTokenCacheItem* tokenCacheItem;

/*! The error that occurred or nil, if the operation was successful */
@property (readonly) ADAuthenticationError* error;

/*! Set to YES, if part of the result contains a refresh token, which is a multi-resource
 refresh token. */
@property (readonly) BOOL multiResourceRefreshToken;

/*! The correlation ID of the request(s) that get this result. */
@property (readonly) NSUUID* correlationId;

@end

