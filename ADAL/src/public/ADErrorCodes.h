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

/*! The class contains an incrementally expanding list of errors */
typedef enum
{
    /*! No error occurred. The value is added to make easier usage of functions that take error code,
     but no error condition occurred.*/
    AD_ERROR_SUCCEEDED = 0,
    
    /*! The method call contains one or more invalid arguments */
    AD_ERROR_INVALID_ARGUMENT = 1,
    
    /*! An unexpected internal error occurred. */
    AD_ERROR_UNEXPECTED = 2,
    
    
    //
    // Server Errors
    //
    
    /*! User needs to re-authorize resource usage. This error is raised when access token cannot
     be obtained without user explicitly re-authorizing, but the developer has called
     acquireTokenSilentWithResource method. To obtain the token, the application will need to call
     acquireTokenWithResource after this error to allow the library to give user abitlity
     to re-authorize (with web UI involved). Use -underlyingError to determine the cause. */
    AD_ERROR_SERVER_USER_INPUT_NEEDED = 100,
    
    /*! An error was raised during the process of validating the authorization authority. */
    AD_ERROR_SERVER_AUTHORITY_VALIDATION = 101,
    
    /*! When work place join is required by the service. */
    AD_ERROR_SERVER_WPJ_REQUIRED = 102,
    
    /*! An OAuth Error was received from the server, use -protocolCode for the error sent by the server. */
    AD_ERROR_SERVER_OAUTH = 103,
    
    /*! The refresh token token was rejected by the server, use -protocoolCode for the error sent by the server. */
    AD_ERROR_SERVER_REFRESH_TOKEN_REJECTED = 104,
    
    /*! The user returned by the server does not match the the user identifier specified by the developer. */
    AD_ERROR_SERVER_WRONG_USER = 105,
    
    /*! Server redirects authentication process to a non-https url */
    AD_ERROR_SERVER_NON_HTTPS_REDIRECT = 106,
    
    AD_ERROR_SERVER_INVALID_ID_TOKEN = 107,
    
    /*! HTTP 401 (Unauthorized) response does not contain the OAUTH2 required header */
    AD_ERROR_SERVER_MISSING_AUTHENTICATE_HEADER = 108,
    
    /*! HTTP 401 (Unauthorized) response's authentication header is in invalid format
     or does not contain expected values. */
    AD_ERROR_SERVER_AUTHENTICATE_HEADER_BAD_FORMAT = 109,
    
    /*! The logic expects the server to return HTTP_UNAUTHORIZED */
    AD_ERROR_SERVER_UNAUTHORIZED_CODE_EXPECTED = 110,
    
    /*! We were asked to do something that is not supported by this version of ADAL. */
    AD_ERROR_SERVER_UNSUPPORTED_REQUEST = 111,
    
    
    //
    // Cache Errors
    //
    
    /*! Access tokens for multiple users exist in the token cache. Please specify the userId. */
    AD_ERROR_CACHE_MULTIPLE_USERS = 200,
    
    /*! The provided cache is from an incompatible future version of ADAL. */
    AD_ERROR_CACHE_VERSION_MISMATCH = 201,
    
    /*! An issue occurred while attempting to read the persisted token cache store. */
    AD_ERROR_CACHE_BAD_FORMAT = 202,
    
    AD_ERROR_CACHE_NO_REFRESH_TOKEN = 203,
    
    
    //
    // UI Errors
    //
    
    /*! ADAL only supports a single interactive auth session at a time. The calling app should never ask for
     interactive auth when ADAL is in the middle of an interactive request */
    AD_ERROR_UI_MULTLIPLE_INTERACTIVE_REQUESTS = 301,
    
    /*! Failed to extract the main view controller of the application. Make sure that the application
     has UI elements.*/
    AD_ERROR_UI_NO_MAIN_VIEW_CONTROLLER = 302,
    
    /*! Interaction (webview/broker) cannot be launched in app extension */
    AD_ERROR_UI_NOT_SUPPORTED_IN_APP_EXTENSION = 303,
    
    /*! The user has cancelled the applicable UI prompts */
    AD_ERROR_UI_USER_CANCEL = 304,
    
    //
    // Broker Errors
    //
    
    /*! The redirect URI cannot be used for invoking broker. */
    AD_ERROR_TOKENBROKER_INVALID_REDIRECT_URI = 401,
    
    /*! When the hash of the decrypted broker response does not match the hash returned from broker. */
    AD_ERROR_TOKENBROKER_RESPONSE_HASH_MISMATCH = 402,
    
    /*! When the application waiting for broker is activated ,without broker response. */
    AD_ERROR_TOKENBROKER_RESPONSE_NOT_RECEIVED = 403,
    
    /*! The error code was not sent to us due to an older version of the broker */
    AD_ERROR_TOKENBROKER_UNKNOWN = 404,
    
    /*! Failed to create the encryption key to talk to Azure Authenticator */
    AD_ERROR_TOKENBROKER_FAILED_TO_CREATE_KEY = 405,
    
    
} ADErrorCode;

/* HTTP status codes used by the library */
typedef enum
{
    HTTP_UNAUTHORIZED = 401,
} HTTPStatusCodes;