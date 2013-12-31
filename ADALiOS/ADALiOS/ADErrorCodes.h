// Created by Boris Vidolov on 10/15/13.
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

/*! The class contains an incrementally expanding list of errors */
typedef enum
{
    /*! No error occurred. The value is added to make easier usage of functions that take error code,
     but no error condition occurred.*/
    AD_ERROR_SUCCEEDED,
    
    /*! The user has cancelled the applicable UI prompts */
    AD_ERROR_USER_CANCEL,
    
    /*! The method call contains one or more invalid arguments */
    AD_ERROR_INVALID_ARGUMENT,
    
    /*! HTTP 401 (Unauthorized) response does not contain the OAUTH2 required header */
    AD_ERROR_MISSING_AUTHENTICATE_HEADER,
    
    /*! HTTP 401 (Unauthorized) response's authentication header is in invalid format
     or does not contain expected values. */
    AD_ERROR_AUTHENTICATE_HEADER_BAD_FORMAT,
    
    /*! An internal error occurs when the library did not receive
     a response from the server */
    AD_ERROR_CONNECTION_MISSING_RESPONSE,
    
    /*! The logic expects the server to return HTTP_UNAUTHORIZED */
    AD_ERROR_UNAUTHORIZED_CODE_EXPECTED,
    
    /*! The refresh token cannot be used for extracting an access token. */
    AD_ERROR_INVALID_REFRESH_TOKEN,
    
    /*! An unexpected internal error occurred. */
    AD_ERROR_UNEXPECTED,
    
    /*! Access tokens for multiple users exist in the token cache. Please specify the userId. */
    AD_ERROR_MULTIPLE_USERS,
    
    /*! User needs to authenticate. This error is raised when access token cannot be obtained
     without user explicitly authenticating, but the acquireToken is called with AD_PROMPT_NEVER
     parameter. To obtain the token, the calling application can retry the call with AD_PROMPT_AUTO
     or AD_PROMPT_ALWAYS at appropriate time/thread. */
    AD_ERROR_USER_INPUT_NEEDED,
    
    /*! The cache store cannot be persisted to the specified location. This error is raised only if
     the application called explicitly to persist the cache. Else, the errors are only logged
     as warnings. */
    AD_ERROR_CACHE_PERSISTENCE,
    
    /*! An issue occurred while attempting to read the persisted token cache store. */
    AD_ERROR_BAD_CACHE_FORMAT,
    
    /*! The user is currently prompted for another authentication. The library chose to raise this
     error instead of waiting to avoid multiple sequential prompts. It is up to the application
     developer to chose to retry later. */
    AD_ERROR_USER_PROMPTED,
    
    /*! This type of error occurs when something went wrong with the application stack, e.g.
     the resource bundle cannot be loaded. */
    AD_ERROR_APPLICATION,
    
    /*! A generic error code for all of the authentication errors. */
    AD_ERROR_AUTHENTICATION,
    
    /*! An error was raised during the process of validating the authorization authority. */
    AD_ERROR_AUTHORITY_VALIDATION,
    
} ADErrorCode;

/* HTTP status codes used by the library */
typedef enum
{
    HTTP_UNAUTHORIZED = 401,
} HTTPStatusCodes;