// Created by Boris Vidolov on 10/10/13.
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
#import <ADAliOS/ADAuthenticationError.h>
#import <ADALiOS/ADUserInformation.h>

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
    NSString* _accessTokenType;
    NSString* _accessToken;
    NSString* _refreshToken;
    NSDate* _expiresOn;
    ADAuthenticationResultStatus _status;
    BOOL _multiResourceRefreshToken;
    ADAuthenticationError* _error;
    NSString* _tenantId;
    ADUserInformation* _userInformation;
}

/*! Type of the obtained access token */
@property (readonly) NSString* accessTokenType;

/*! May be nil, if status is not AD_SUCCESS */
@property (readonly) NSString* accessToken;

/*! May be nil, if status is not AD_SUCCESS or if the authority didn't issue a refresh token. */
@property (readonly) NSString* refreshToken;

/*! The point of time when the accessToken will expire. */
@property (readonly) NSDate* expiresOn;

/*! See the ADAuthenticationResultStatus details */
@property (readonly) ADAuthenticationResultStatus status;

/*! Indicates that the refresh token may be used for requesting access token for other resources. */
@property (readonly) BOOL multiResourceRefreshToken;

/*! The error that occurred or nil, if the operation was successful */
@property (readonly) ADAuthenticationError* error;

/*! The identifier for the tenant for which the token was acquired. 
 May be nil if the tenant was not returned by the service */
@property (readonly) NSString* tenantId;

/*! Provides information about the user that was authenticated */
@property (readonly) ADUserInformation* userInformation;

@end

