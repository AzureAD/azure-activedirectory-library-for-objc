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
typedef NS_ENUM(NSInteger, ADErrorCode)
{
    /*! No error occurred. The value is added to make easier usage of functions that take error code,
     but no error condition occurred.*/
    AD_ERROR_SUCCEEDED = 0,
    
    /*! An unexpected internal error occurred. */
    AD_ERROR_UNEXPECTED = -1,
    
    //
    // Developer Errors
    // These errors occur from bad parameters given by the developer
    //
    
    /*! The method call contains one or more invalid arguments */
    AD_ERROR_DEVELOPER_INVALID_ARGUMENT = 100,
    
    /*! The passed in authority URL does not pass validation, if you're trying to use ADFS directly you must disable authority validation. */
    /*! An error was raised during the process of validating the authorization authority. */
    AD_ERROR_DEVELOPER_AUTHORITY_VALIDATION = 101,
    
    
    //
    // Server Errors
    // These errors result from interaction with or errors returned directly
    // by the server.
    //
    
    /*! User needs to re-authorize resource usage. This error is raised when access token cannot
     be obtained without user explicitly re-authorizing, but the developer has called
     acquireTokenSilentWithResource method. To obtain the token, the application will need to call
     acquireTokenWithResource after this error to allow the library to give user abitlity
     to re-authorize (with web UI involved). */
    AD_ERROR_SERVER_USER_INPUT_NEEDED = 200,
    
    /*! When work place join is required by the service. */
    AD_ERROR_SERVER_WPJ_REQUIRED = 201,
    
    /*! An OAuth Error was received from the server, use -protocolCode for the error sent by the server. */
    AD_ERROR_SERVER_OAUTH = 202,
    
    /*! The refresh token token was rejected by the server, use -protocoolCode for the error sent by the server. */
    AD_ERROR_SERVER_REFRESH_TOKEN_REJECTED = 203,
    
    /*! The user returned by the server does not match the the user identifier specified by the developer. */
    AD_ERROR_SERVER_WRONG_USER = 204,
    
    /*! Server redirects authentication process to a non-https url */
    AD_ERROR_SERVER_NON_HTTPS_REDIRECT = 205,
    
    /*! The server sent us an idtoken that we were unable to parse. */
    AD_ERROR_SERVER_INVALID_ID_TOKEN = 206,
    
    /*! HTTP 401 (Unauthorized) response does not contain the OAUTH2 required header */
    AD_ERROR_SERVER_MISSING_AUTHENTICATE_HEADER = 207,
    
    /*! HTTP 401 (Unauthorized) response's authentication header is in invalid format
     or does not contain expected values. */
    AD_ERROR_SERVER_AUTHENTICATE_HEADER_BAD_FORMAT = 208,
    
    /*! The logic expects the server to return HTTP_UNAUTHORIZED */
    AD_ERROR_SERVER_UNAUTHORIZED_CODE_EXPECTED = 209,
    
    /*! We were asked to do something that is not supported by this version of ADAL. */
    AD_ERROR_SERVER_UNSUPPORTED_REQUEST = 210,
    
    /*! A failure occurred while trying to get an authorization code */
    AD_ERROR_SERVER_AUTHORIZATION_CODE = 211,
    
    /*! Invalid data was returned from the server, see -errorDetails for more information. */
    AD_ERROR_SERVER_INVALID_RESPONSE = 212,

    /*! The requested resource is protected by an Intune Conditional Access policy.
     The calling app should integrate the Intune SDK and call the remediateComplianceForIdentity:silent: API,
     please see https://aka.ms/intuneMAMSDK for more information. */
    AD_ERROR_SERVER_PROTECTION_POLICY_REQUIRED = 213,
    
    
    //
    // Cache Errors
    // These errors originate from a non-recoverable or ambiguous interaction
    // with the cache.
    //
    
    /*! Access tokens for multiple users exist in the token cache. Please specify the userId. */
    AD_ERROR_CACHE_MULTIPLE_USERS = 300,
    
    /*! The provided cache is from an incompatible future version of ADAL. */
    AD_ERROR_CACHE_VERSION_MISMATCH = 301,
    
    /*! An issue occurred while attempting to read the persisted token cache store. */
    AD_ERROR_CACHE_BAD_FORMAT = 302,
    
    /*! No refresh token was available in the cache */
    AD_ERROR_CACHE_NO_REFRESH_TOKEN = 303,
    
    
    //
    // UI Errors
    // These errors originate from either being unable to display the user
    // interface, or a user interaction.
    //
    
    /*! ADAL only supports a single interactive auth session at a time. The calling app should never ask for
     interactive auth when ADAL is in the middle of an interactive request */
    AD_ERROR_UI_MULTLIPLE_INTERACTIVE_REQUESTS = 400,
    
    /*! Failed to extract the main view controller of the application. Make sure that the application
     has UI elements.*/
    AD_ERROR_UI_NO_MAIN_VIEW_CONTROLLER = 401,
    
    /*! Interaction (webview/broker) cannot be launched in app extension */
    AD_ERROR_UI_NOT_SUPPORTED_IN_APP_EXTENSION = 402,
    
    /*! The user has cancelled the applicable UI prompts */
    AD_ERROR_UI_USER_CANCEL = 403,
    
    /*! Interactive authentication requests must originate on the main thread. */
    AD_ERROR_UI_NOT_ON_MAIN_THREAD = 404,
    
    //
    // Token Broker Errors
    // These errors originate from being unable or failing to communicate with
    // the token broker (Azure Authenticator).
    //
    
    /*! The error code was not sent to us due to an older version of the broker */
    AD_ERROR_TOKENBROKER_UNKNOWN = 500,
    
    /*! The redirect URI cannot be used for invoking broker. */
    AD_ERROR_TOKENBROKER_INVALID_REDIRECT_URI = 501,
    
    /*! When the hash of the decrypted broker response does not match the hash returned from broker. */
    AD_ERROR_TOKENBROKER_RESPONSE_HASH_MISMATCH = 502,
    
    /*! When the application waiting for broker is activated ,without broker response. */
    AD_ERROR_TOKENBROKER_RESPONSE_NOT_RECEIVED = 503,
    
    /*! Failed to create the encryption key to talk to Azure Authenticator */
    AD_ERROR_TOKENBROKER_FAILED_TO_CREATE_KEY = 504,
    
    /*! Failed to decrypt the message we received from Azure Authenticator */
    AD_ERROR_TOKENBROKER_DECRYPTION_FAILED = 505,
    
    /*! We were launched with a URL, however that URL did not come from the broker app, or was
        not a broker response. */
    AD_ERROR_TOKENBROKER_NOT_A_BROKER_RESPONSE = 506,
    
    /*! No resume dictionary was found in NSUserDefaults, so either we aren't expecting a broker response, or something else unexpected happened */
    AD_ERROR_TOKENBROKER_NO_RESUME_STATE = 507,
    
    /*! Missing data from the broker response resume dictionary */
    AD_ERROR_TOKENBROKER_BAD_RESUME_STATE = 508,
    
    /*! Data from the broker response does not match the resume state from our broker request */
    AD_ERROR_TOKENBROKER_MISMATCHED_RESUME_STATE = 509,
    
    /*! The key hash was missing from the response */
    AD_ERROR_TOKENBROKER_HASH_MISSING = 510,
    
    /*! We can't call out to tokenbroker in an extension */
    AD_ERROR_TOKENBROKER_NOT_SUPPORTED_IN_EXTENSION = 511,

    
};

/* HTTP status codes used by the library */
typedef enum
{
    HTTP_UNAUTHORIZED = 401,
} HTTPStatusCodes;
