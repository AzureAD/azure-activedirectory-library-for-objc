/*
 Copyright © 2012 Microsoft. All rights reserved.
 
 Synopsis: Global constants for common ios library
 
 Owner: yiweizha
 Created: 9/26/2013
 */

// Domains for the components within the common ios library.

#define CUT_DOMAIN_BASE @"com.microsoft.commonlib"

NSString *const kCUTAdalDomain = CUT_DOMAIN_BASE @".adalsdk";
NSString *const kCUTAuthenticationDomain = CUT_DOMAIN_BASE @".authentication";
NSString *const kCUTHttpConnectorDomain = CUT_DOMAIN_BASE @".httpconnector";
NSString *const kCUTLoggerDomain = CUT_DOMAIN_BASE @".logger";
NSString *const kCUTUtilityDomain = CUT_DOMAIN_BASE @".utility";

// Error user info for http connector 
NSString *const kCUTErrorUserInfo_ClientRequestId = @"ClientRequestId";
NSString *const kCUTErrorUserInfo_ServerResponseId = @"ServerResponseId";
