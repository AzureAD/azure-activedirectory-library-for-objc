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

// HTTP Wrappers
#import "HTTPWebRequest.h"
#import "HTTPWebResponse.h"

#import "IPAuthorization.h"
#import "IPAuthorizationCache.h"

#import "IPConstants.h"
#import "IPAuthenticationResult.h"
#import "IPAuthenticationSettings.h"

#import "WebAuthenticationBroker.h"

#import "IPAuthenticationContext.h"

#import "NSString+ADHelperMethods.h"

// Extension methods
#import "NSDictionaryExtensions.h"
#import "NSStringExtensions.h"
#import "NSURLExtensions.h"
#import "IPAuthorization.h"

// OS Headers
#include <libkern/OSAtomic.h>

//
// Private declaration that this class implements several delegate protocols
//
@interface IPAuthenticationContext ()

// Generic OAuth2 Authorization Request
+ (void)requestAuthorization:(NSString *)authorizationServer responseType:(NSString *)response_type resource:(NSString *)resource scope:(NSString *)scope webView:(SysWebView *)webView completion:( AuthorizationCallback )completionBlock;

// Generic OAuth2 Token Request using an Authorization Code
+ (void)requestToken:(IPAuthorization *)authorization completion:( void (^)(IPAuthenticationResult *))completionBlock;

// Performs an HTTP POST request to the target server using the supplied request dictionary and executes the completion block
+ (void)request:(NSString *)authorizationServer requestData:(NSDictionary *)request_data completion:( void (^)(NSDictionary *) )completionBlock;

// Protocol state encoding and decoding
+ (NSDictionary *)decodeProtocolState:(NSString *)encodedState;
+ (NSString *)encodeProtocolState:(NSString *)authorizationServer resource:(NSString *)resource scope:(NSString *)scope;

// Helpers for dispatching delegates/blocks. Change these method implementation to change the thread
// that delegates/blocks are dispatched on. See comments in the method implementation.
+ (void)dispatchCallback:(AuthorizationCallback)callback withResult:(IPAuthenticationResult *)result;

// Helper methods
+ (void)assertMainThread:(NSString *)message;
+ (NSString *)validateAuthorizationURL:(NSString *)authorizationURL;

@end

static int                   _active          = 0;
static AuthorizationCallback _completionBlock = nil;

@implementation IPAuthenticationContext
{
}

#pragma mark - Cache Management

+ (IPAuthorization *)authorizationForKey:(NSString *)key
{
    if ( [self settings].enableTokenCaching == NO )
        return nil;
    
    //
    // Check the token cache for an existing token that meets requirements.
    //
    IPAuthorization *authorization = [[self settings].authorizationCache authorizationForKey:key];
    
    if ( authorization != nil )
    {
        if ( ( authorization.isExpired && !authorization.isRefreshable ) )
        {
            // Remove dead authorizations
            [[self settings].authorizationCache removeAuthorizationForKey:authorization.cacheKey];
            authorization = nil;
        }
    }
    
    return authorization;
}

+ (void)setAuthorization:(IPAuthorization *)authorization forKey:(NSString *)key
{
    if ( [[self settings] enableTokenCaching] == NO )
        return;
    
    [[self settings].authorizationCache setAuthorization:authorization forKey:key];
}

+ (void)removeAuthorizationForKey:(NSString *)key
{
    [[self settings].authorizationCache removeAuthorizationForKey:key];
}

+ (void)removeAllAuthorizations
{
    [[self settings].authorizationCache removeAllAuthorizations];
}

#pragma mark - Public Methods

+ (void)cancelRequestAuthorization
{
    // Release the exclusion lock, if it is taken
    if ( _active )
    {
        [[WebAuthenticationBroker sharedInstance] cancel];
    }
}

// OAuth2 Authorization Request using default mechanisms.
// This API must be called from the applications main thread, the delegate is always called on the main thread.
// This API performs token caching.
+ (void)requestAuthorization:(NSString *)authorizationServer resource:(NSString *)resource scope:(NSString *)scope completion:( void (^)(IPAuthenticationResult *) )completionBlock
{
    [self requestAuthorization:authorizationServer resource:resource scope:scope webView:nil completion:completionBlock];
}

// OAuth2 Authorization Request using default mechanisms, using a WebView hosted by the application.
// This API must be called from the applications main thread, the delegate is always called on the main thread.
+ (void)requestAuthorization:(NSString *)authorizationServer resource:(NSString *)resource scope:(NSString *)scope webView:(SysWebView *)webView completion:( AuthorizationCallback )completionBlock
{
    [[self class] assertMainThread:[NSString stringWithFormat:@"IPAuthenticationContext %@ must be called on the main thread", NSStringFromSelector(_cmd)]];
    
    // No delegate is halting condition
    if ( nil == completionBlock )
    {
        NSAssert( false, @"Must supply completion block object" );
        @throw [NSException exceptionWithName:NSInternalInconsistencyException reason:@"Must supply completion block object" userInfo:nil];
    }
    
    // Verify client_id
    if ( [self settings].clientId == nil || [self settings].clientId.length == 0 )
    {
        [self dispatchCallback:completionBlock withResult:[[IPAuthenticationResult alloc] initWithError:AUTH_FAILED description:AUTH_FAILED_NO_CLIENTID]];
        return;
    }
    
    // Verify redirect_uri
    if ( [self settings].redirectUri == nil || [self settings].redirectUri.length == 0 )
    {
        [self dispatchCallback:completionBlock withResult:[[IPAuthenticationResult alloc] initWithError:AUTH_FAILED description:AUTH_FAILED_NO_REDIRECTURI]];
        return;
    }
    
    // Validate the authorization server URI
    NSString *authorizationServerBase = [self validateAuthorizationURL:authorizationServer];
    
    if ( !authorizationServerBase )
    {
        [self dispatchCallback:completionBlock withResult:[[IPAuthenticationResult alloc] initWithError:AUTH_FAILED description:AUTH_FAILED_BAD_PARAMETERS]];
        return;
    }
    
    // resource cannot be nil or empty
    if ( resource == nil || resource.length == 0 )
    {
        [self dispatchCallback:completionBlock withResult:[[IPAuthenticationResult alloc] initWithError:AUTH_FAILED description:AUTH_FAILED_BAD_PARAMETERS]];
        return;
    }
    
    [self requestAuthorization:authorizationServerBase responseType:OAUTH2_CODE resource:resource scope:scope webView:webView completion:^(IPAuthenticationResult *result) {
        // Use the code to obtain a token.
        if ( result.status == AuthenticationSucceeded )
        {
            NSAssert( result.authorization.code, @"Expected an authorization_code" );
            
            [IPAuthenticationContext requestToken:result.authorization completion:^(IPAuthenticationResult *result) {
                
                if ( result.status == AuthenticationSucceeded )
                {
                    [self setAuthorization:result.authorization forKey:result.authorization.cacheKey];
                }
                
                [self dispatchCallback:completionBlock withResult:result];
            }];
        }
        else
        {
            [self dispatchCallback:completionBlock withResult:result];
        }
    }];
}


// Generic OAuth2 Token Request using a Refresh Token
// This API must be called from the applications main thread, the delegate is always called on the main thread.
+ (void)refreshAuthorization:(IPAuthorization *)authorization completion:( void (^)(IPAuthenticationResult *))completionBlock
{
    // No delegate is halting condition
    if ( nil == completionBlock )
    {
        @throw [NSException exceptionWithName:NSInvalidArgumentException reason:@"Must supply completion block object" userInfo:nil];
    }
    
    if ( !authorization || !authorization.isRefreshable )
    {
        [self dispatchCallback:completionBlock withResult:[[IPAuthenticationResult alloc] initWithError:AUTH_FAILED description:AUTH_FAILED_BAD_PARAMETERS]];
        return;
    }
    
    // Verify client_id
    if ( [self settings].clientId == nil || [self settings].clientId.length == 0 )
    {
        [self dispatchCallback:completionBlock withResult:[[IPAuthenticationResult alloc] initWithError:AUTH_FAILED description:AUTH_FAILED_NO_CLIENTID]];
        return;
    }
    
    // Verify redirect_uri
    if ( [self settings].redirectUri == nil || [self settings].redirectUri.length == 0 )
    {
        [self dispatchCallback:completionBlock withResult:[[IPAuthenticationResult alloc] initWithError:AUTH_FAILED description:AUTH_FAILED_NO_REDIRECTURI]];
        return;
    }
    
    NSMutableDictionary *request_data = [NSMutableDictionary dictionaryWithObjectsAndKeys:@"refresh_token", @"grant_type",
                                         authorization.refreshToken, @"refresh_token",
                                         [self settings].clientId, @"client_id",
                                         nil];
    
    // Append platform_id if it has been set
    if ( [self settings].platformId != nil )
    {
        [request_data setObject:[self settings].platformId forKey:@"platform_id"];
    }
    
    [self request:authorization.authorizationServer requestData:request_data completion:^(NSDictionary *response) {
        IPAuthenticationResult *result = [self processResponse:response forAuthorization:authorization];
        
        if ( result.status == AuthenticationSucceeded )
            [self setAuthorization:result.authorization forKey:result.authorization.cacheKey];
        
        completionBlock( result );
    }];
}


// Generic OAuth2 Authorization + Token Request
// This API will attempt to find a cached Authorization first and refresh it if necessary. If no cached Authorization
// can be found, or the refresh fails, the API will request a new Authorization. In effect, this API is a combination
// of authorizationForKey:, refreshAuthorization:completion: and requestAuthorization:resource:scope:completion.
// This API must be called from the applications main thread, the delegate is always called on the main thread.
+ (void)requestAccessToken:(NSString *)authorizationServer resource:(NSString *)resource scope:(NSString *)scope webView:(SysWebView *)webView completion:( AuthorizationCallback )completionBlock
{
    [[self class] assertMainThread:[NSString stringWithFormat:@"IPAuthenticationContext %@ must be called on the main thread", NSStringFromSelector(_cmd)]];
    
    // No delegate is halting condition
    if ( nil == completionBlock )
    {
        NSAssert( false, @"Must supply completion block object" );
        @throw [NSException exceptionWithName:NSInternalInconsistencyException reason:@"Must supply completion block object" userInfo:nil];
    }
    
    // Verify client_id
    if ( [self settings].clientId == nil || [self settings].clientId.length == 0 )
    {
        [self dispatchCallback:completionBlock withResult:[[IPAuthenticationResult alloc] initWithError:AUTH_FAILED description:AUTH_FAILED_NO_CLIENTID]];
        return;
    }
    
    // Verify redirect_uri
    if ( [self settings].redirectUri == nil || [self settings].redirectUri.length == 0 )
    {
        [self dispatchCallback:completionBlock withResult:[[IPAuthenticationResult alloc] initWithError:AUTH_FAILED description:AUTH_FAILED_NO_REDIRECTURI]];
        return;
    }
    
    // Validate the authorization server URI
    NSString *authorizationServerBase = [self validateAuthorizationURL:authorizationServer];
    
    if ( !authorizationServerBase )
    {
        [self dispatchCallback:completionBlock withResult:[[IPAuthenticationResult alloc] initWithError:AUTH_FAILED description:AUTH_FAILED_BAD_PARAMETERS]];
        return;
    }
    
    // resource cannot be nil or empty
    if ( resource == nil || resource.length == 0 )
    {
        [self dispatchCallback:completionBlock withResult:[[IPAuthenticationResult alloc] initWithError:AUTH_FAILED description:AUTH_FAILED_BAD_PARAMETERS]];
        return;
    }

    // Attempt to find an Authorization in the cache
    IPAuthorization *authorization = [self authorizationForKey:[IPAuthorization cacheKeyForServer:authorizationServerBase resource:resource scope:scope]];
    
    if ( !authorization )
    {
        // No usable Authorization was found. The only option now is to request a new one.
        [self requestAuthorization:authorizationServer resource:resource scope:scope webView:webView completion:completionBlock];
    }
    else
    {
        // An authorization was found. If it is expired but refreshable, attempt a refresh. Note that authorizationForKey will *never*
        // return Expired authorizations that cannot be refreshed. If that semantic changes then this code will break.
        if ( [authorization isExpired] )
        {
            [self refreshAuthorization:authorization completion:^(IPAuthenticationResult *result) {
                if ( result.status == AuthenticationSucceeded )
                {
                    // Refresh succeeded
                    [self dispatchCallback:completionBlock withResult:result];
                }
                else
                {
                    // Refresh Failed. The only option now is to request a new one.
                    [self requestAuthorization:authorizationServer resource:resource scope:scope webView:webView completion:completionBlock];
                }
            }];
        }
        else
        {
            // An unexpired Authorization was found.
            [self dispatchCallback:completionBlock withResult:[[IPAuthenticationResult alloc] initWithAuthorization:authorization]];
        }
    }
}


// Gets the settings for the AuthorizationContext
+ (IPAuthenticationSettings *)settings
{
    return [IPAuthenticationSettings sharedInstance];
}

#pragma mark - Internal Methods

+ (IPAuthenticationResult *)processResponse:(NSDictionary *)response forAuthorization:(IPAuthorization *)authorization
{
    IPAuthenticationResult *result = nil;
    
    if ( [response objectForKey:OAUTH2_ERROR] != nil )
    {
        // Error response from the server
        // TODO: Should we kill the authorization object?
        result = [[IPAuthenticationResult alloc] initWithError:[response objectForKey:OAUTH2_ERROR] description:[response objectForKey:OAUTH2_ERROR_DESCRIPTION]];
    }
    else if ( [response objectForKey:OAUTH2_CODE] != nil )
    {
        // Code response
        authorization.accessToken     = nil;
        authorization.accessTokenType = nil;
        authorization.code            = [response objectForKey:OAUTH2_CODE];
        authorization.expires         = [NSDate dateWithTimeIntervalSinceNow:300];
        authorization.refreshToken    = nil;
        
        result = [[IPAuthenticationResult alloc] initWithAuthorization:authorization];
    }
    else if ( [response objectForKey:OAUTH2_ACCESS_TOKEN] != nil )
    {
        // Token response
        id      expires_in = [response objectForKey:@"expires_in"];
        NSDate *expires    = nil;
        
        if ( expires_in != nil )
        {
            if ( [expires_in isKindOfClass:[NSString class]] )
            {
                NSNumberFormatter *formatter = [[NSNumberFormatter alloc] init];
                
                expires = [NSDate dateWithTimeIntervalSinceNow:[formatter numberFromString:expires_in].longValue];
            }
            else if ( [expires_in isKindOfClass:[NSNumber class]] )
            {
                expires = [NSDate dateWithTimeIntervalSinceNow:((NSNumber *)expires_in).longValue];
            }
            else
            {
                // Unparseable, use default value
                expires = [NSDate dateWithTimeIntervalSinceNow:3600.0];
            }
        }
        else
        {
            expires = [NSDate dateWithTimeIntervalSinceNow:3600.0];
        }
        
        authorization.accessToken     = [response objectForKey:OAUTH2_ACCESS_TOKEN];
        authorization.accessTokenType = [response objectForKey:OAUTH2_TOKEN_TYPE];
        authorization.code            = nil;
        authorization.expires         = expires;
        
        if ( [response objectForKey:OAUTH2_REFRESH_TOKEN] )
            authorization.refreshToken    = [response objectForKey:OAUTH2_REFRESH_TOKEN];
        
        result = [[IPAuthenticationResult alloc] initWithAuthorization:authorization];
    }
    else
    {
        // TODO: Should we kill the authorization object?
        result = [[IPAuthenticationResult alloc] initWithError:AUTH_FAILED description:AUTH_FAILED_SERVER_ERROR];
    }
    
    return result; ;
}

// Generic OAuth2 Authorization Request
+ (void)requestAuthorization:(NSString *)authorizationServerBase responseType:(NSString *)response_type resource:(NSString *)resource scope:(NSString *)scope webView:(SysWebView *)webView completion:(AuthorizationCallback)completionBlock
{
    // response_type must be one of code or token
    if ( response_type == nil || response_type.length == 0 || !( [response_type isEqualToString:@"code"] || [response_type isEqualToString:@"token"] ) )
    {
        [self dispatchCallback:completionBlock withResult:[[IPAuthenticationResult alloc] initWithError:AUTH_FAILED description:AUTH_FAILED_BAD_PARAMETERS]];
        return;
    }
    
    // Take exclusion lock
    if ( !OSAtomicCompareAndSwapInt( 0, 1, &_active) )
    {
        [self dispatchCallback:completionBlock withResult:[[IPAuthenticationResult alloc] initWithError:AUTH_FAILED description:AUTH_FAILED_BUSY]];
        return;
    }
    
    // Remember request state early: we need this if we find a cached token and we need it on the final
    // response from the authorization server so that we can wire the result and cache correctly
    NSString *state    = [self encodeProtocolState:authorizationServerBase resource:resource scope:scope];
    
    // Start the web navigation process for the Implicit grant profile.
    NSString *startURL = [NSString stringWithFormat:@"%@?response_type=%@&client_id=%@&resource=%@&redirect_uri=%@&state=%@",
                          [authorizationServerBase stringByAppendingString:@"/authorize"],
                          response_type,
                          [self settings].clientId,
                          [resource URLFormEncode],
                          [[self settings].redirectUri URLFormEncode],
                          state];
    
    // Append platform_id if it has been set
    if ( [self settings].platformId != nil )
    {
        startURL = [startURL stringByAppendingString:[NSString stringWithFormat:@"&platform_id=%@", [[self settings].platformId URLFormEncode]]];
    }
    
    _completionBlock = [completionBlock copy];
    
    [[WebAuthenticationBroker sharedInstance] start:[NSURL URLWithString:startURL]
                                                end:[NSURL URLWithString:[self settings].redirectUri]
                                            ssoMode:self.settings.enableSSO
                                            webView:webView
                                         fullScreen:self.settings.enableFullscreen
                                         completion:^( NSError *error, NSURL *end ) {
        // Release exclusion lock
        if ( !OSAtomicCompareAndSwapInt( 1, 0, &_active) )
            DebugLog( @"Logic error resetting active state" );
        
        // Local to the block
        IPAuthenticationResult *result = nil;
        
        if ( nil != error )
        {
            // Set up the result, a local copy of the delegate, and clear the stored delegate
            result = [[IPAuthenticationResult alloc] initWithError:[error.userInfo objectForKey:@"error"]
                                                       description:[error.userInfo objectForKey:@"error_description"]
                                                            status:(int)error.code];
        }
        else
        {
            // Two options for finding the response: if the profile is Implicit, then the
            // response parameters must be in the URL fragment; if the profile is Code then
            // the response parameters must be in the URL query.
            NSDictionary *parameters = [end fragmentParameters];
            
            // If nothing in the fragment, try the URL query
            if ( parameters.count == 0 ) parameters = [end queryParameters];
            
            // Extract the state dictinary
            NSDictionary *state = [self.class decodeProtocolState:[parameters objectForKey:@"state"]];
            
            if ( nil != state && state.count != 0 )
            {
                NSString *authorizationServer = [state objectForKey:@"a"];
                NSString *resource            = [state objectForKey:@"r"];
                NSString *scope               = [state objectForKey:@"s"];
                
                if ( ( nil != authorizationServer && authorizationServer.length > 0 ) && ( nil != resource && resource.length > 0 ) )
                {
                    // We have decoded state, process the response
                    IPAuthorization *authorization = [[IPAuthorization alloc] initWithServer:authorizationServer resource:resource scope:scope];
                    
                    result = [self processResponse:parameters forAuthorization:authorization];
                    
                    if ( result.status == AuthenticationSucceeded )
                    {
                        // Sanity check that we code the response_type that was expected.
                        if ( [response_type isEqualToString:OAUTH2_CODE] && [NSString isNilOrEmpty:authorization.code] )
                            result = [[IPAuthenticationResult alloc] initWithError:AUTH_FAILED description:AUTH_FAILED_SERVER_ERROR status:AuthenticationFailed];
                        else if ( [response_type isEqualToString:OAUTH2_TOKEN] && [NSString isNilOrEmpty:authorization.accessToken] )
                           result = [[IPAuthenticationResult alloc] initWithError:AUTH_FAILED description:AUTH_FAILED_SERVER_ERROR status:AuthenticationFailed];
                    }
                }
                else
                {
                    // The response from the server was missing data in the state parameter
                    result = [[IPAuthenticationResult alloc] initWithError:AUTH_FAILED description:AUTH_FAILED_NO_STATE];
                }
            }
            else
            {
                // The response from the server had no state information
                result = [[IPAuthenticationResult alloc] initWithError:AUTH_FAILED description:AUTH_FAILED_BAD_STATE];
            }
        }
        
        // Dispatch the delegate
        [self dispatchCallback:_completionBlock withResult:result];
    }];
}

// Generic OAuth2 Token Request using an Authorization Code
// This is an internal API and does NOT perform token caching.
+ (void)requestToken:(IPAuthorization *)authorization completion:(AuthorizationCallback)completionBlock
{
    [[self class] assertMainThread:[NSString stringWithFormat:@"IPAuthenticationContext %@ must be called on the main thread", NSStringFromSelector(_cmd)]];
    
    // No delegate is halting condition
    if ( nil == completionBlock )
    {
        @throw [NSException exceptionWithName:NSInternalInconsistencyException reason:@"Must supply completion block object" userInfo:nil];
    }
    
    // Validate the authorization object
    if ( !authorization || authorization.code == nil || authorization.code.length == 0 )
    {
        [self dispatchCallback:completionBlock withResult:[[IPAuthenticationResult alloc] initWithError:AUTH_FAILED description:AUTH_FAILED_BAD_PARAMETERS]];
        return;
    }
    
    // Determine client_id
    if ( [self settings].clientId == nil || [self settings].clientId.length == 0 )
    {
        [self dispatchCallback:completionBlock withResult:[[IPAuthenticationResult alloc] initWithError:AUTH_FAILED description:AUTH_FAILED_NO_CLIENTID]];
        return;
    }
    
    NSMutableDictionary *request_data = [NSMutableDictionary dictionaryWithObjectsAndKeys:@"authorization_code", @"grant_type",
                                         authorization.code, @"code",
                                         [self settings].clientId, @"client_id",
                                         [self settings].redirectUri, @"redirect_uri",
                                         nil];
    
    // Append platform_id if it has been set
    if ( [self settings].platformId != nil )
    {
        [request_data setObject:[self settings].platformId forKey:@"platform_id"];
    }
    
    [self request:authorization.authorizationServer requestData:request_data completion:^(NSDictionary *response) {
        IPAuthenticationResult *result = [self processResponse:response forAuthorization:authorization];
        completionBlock( result );
    }];
}

// Performs an OAuth2 token request using the supplied request dictionary and executes the completion block
+ (void)request:(NSString *)authorizationServer requestData:(NSDictionary *)request_data completion:( void (^)(NSDictionary *) )completionBlock
{
    // Generate a client-request-id
    CFUUIDRef uuid = CFUUIDCreate(kCFAllocatorDefault);
    NSString *uuidString = (__bridge_transfer NSString *)CFUUIDCreateString(kCFAllocatorDefault, uuid);
    CFRelease(uuid);
    
    DebugLog( @"Sending POST request to %@ with client-request-id %@", [authorizationServer stringByAppendingString:@"/token"], uuidString );
    
    HTTPWebRequest *webRequest = [[HTTPWebRequest alloc] initWithURL:[NSURL URLWithString:[authorizationServer stringByAppendingString:@"/token"]]];
    
    webRequest.method = HTTPPost;
    [webRequest.headers setObject:@"application/json" forKey:@"Accept"];
    [webRequest.headers setObject:@"application/x-www-form-urlencoded" forKey:@"Content-Type"];
    [webRequest.headers setObject:uuidString forKey:@"client-request-id"];
    
    webRequest.body = [[request_data URLFormEncode] dataUsingEncoding:NSUTF8StringEncoding];
    
    [webRequest send:^( NSError *error, HTTPWebResponse *webResponse ) {
        // Request completion callback
        NSDictionary *response = nil;
        
        if ( error == nil )
        {
            if ( webResponse.statusCode == 200 || webResponse.statusCode == 400 )
            {
                NSError   *jsonError  = nil;
                id         jsonObject = [NSJSONSerialization JSONObjectWithData:webResponse.body options:0 error:&jsonError];
                
                if ( nil != jsonObject && [jsonObject isKindOfClass:[NSDictionary class]] )
                {
                    // Load the response
                    response = (NSDictionary *)jsonObject;
                }
                else
                {
                    // Unrecognized JSON response
                    NSMutableDictionary *mutableResponse = [[NSMutableDictionary alloc] initWithCapacity:2];
                    [mutableResponse setObject:AUTH_FAILED forKey:OAUTH2_ERROR];
                    [mutableResponse setObject:jsonError.localizedDescription forKey:OAUTH2_ERROR_DESCRIPTION];
                    
                    response = mutableResponse;
                }
            }
            else
            {
                // Request failure
                DebugLog( @"Server HTTP Status %ld", (long)webResponse.statusCode );
                DebugLog( @"Server HTTP Response %@", [[NSString alloc] initWithData:webResponse.body encoding:NSUTF8StringEncoding] );

                NSMutableDictionary *mutableResponse = [[NSMutableDictionary alloc] initWithCapacity:2];
                [mutableResponse setObject:AUTH_FAILED forKey:OAUTH2_ERROR];
                [mutableResponse setObject:AUTH_FAILED_SERVER_ERROR forKey:OAUTH2_ERROR_DESCRIPTION];
                
                response = mutableResponse;
            }
        }
        else
        {
            // System error
            NSMutableDictionary *mutableResponse = [[NSMutableDictionary alloc] initWithCapacity:2];
            [mutableResponse setObject:AUTH_FAILED forKey:OAUTH2_ERROR];
            [mutableResponse setObject:error.localizedDescription forKey:OAUTH2_ERROR_DESCRIPTION];
            
            response = mutableResponse;
        }

        completionBlock( response );
    }];
}

// Verify we are running on the main thread and abort with a message otherwise
+ (void)assertMainThread:(NSString *)message
{
    if (![[NSThread currentThread] isEqual:[NSThread mainThread]])
    {
        NSAssert(false, message);
        @throw [NSException exceptionWithName:NSInternalInconsistencyException reason:message userInfo:nil];
    }
}

// Decodes the state parameter from a protocol message
+ (NSDictionary *)decodeProtocolState:(NSString *)encodedState
{
    return [NSDictionary URLFormDecode:[encodedState adBase64Decode]];
}

// Encodes the state parameter for a protocol message
+ (NSString *)encodeProtocolState:(NSString *)authorizationServer resource:(NSString *)resource scope:(NSString *)scope
{
    return [[[NSMutableDictionary dictionaryWithObjectsAndKeys:authorizationServer, @"a", resource, @"r", scope, @"s", nil]
                URLFormEncode] adBase64Encode];
}

// Dispatch the callback
+ (void)dispatchCallback:(AuthorizationCallback)callback withResult:(IPAuthenticationResult *)result
{
    // Choose between these two lines: the first is main queue dispatch, the second background thread dispatch
    // Why no dispatch_async for the first line? Because the only way here is on the main thread anyway
    callback( result );
    //dispatch_async( dispatch_get_main_queue(), ^{ callback( result ); } );
}

// Validate an Authorization URL passed as a string
+ (NSString *)validateAuthorizationURL:(NSString *)authorizationURL
{
    if ( authorizationURL == nil || authorizationURL.length == 0 )
        return nil;
    
    NSURL *url = [NSURL URLWithString:authorizationURL];
    
    if ( url == nil || url.baseURL != nil )
        return nil;
    
    if ( ![url.scheme isEqualToString:@"https"] )
        return nil;
    
    if ( url.fragment != nil )
        return nil;
    
    if ( url.query != nil )
        return nil;

    return [IPAuthorization normalizeAuthorizationServer:authorizationURL];
}

@end
