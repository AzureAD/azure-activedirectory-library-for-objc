/*
 Copyright © 2012 Microsoft. All rights reserved.
 
 Synopsis: Global constants for common ios library
 
 Owner: yiweizha
 Created: 9/26/2013
 */

/**
 @details Event IDs for tracing.
 */

#import <Foundation/Foundation.h>
typedef NS_ENUM(NSUInteger, CUTTraceEventId)
{
    CUTTraceEventIdDefault           = 0,
    
    // Http related event
    CUTTraceEventIdHttp              = 100,
    
    // Authentication related event
    CUTTraceEventIdAuthentication    = 200,
    CUTTraceEventIdSignIn            = 201,
    CUTTraceEventIdSignOut           = 202,
    CUTTraceEventIdTokenRenewal      = 203,
    CUTTraceEventIdTokenFetch        = 204,
};


// Domains for the utility within the common ios library.
extern NSString *const kCUTUtilityDomain;

// // Error user info for http connector
extern NSString *const kCUTErrorUserInfo_ClientRequestId;
extern NSString *const kCUTErrorUserInfo_ServerResponseId;
