
#import <ADAL/ADAL.h>
#import "AuthenticationService.h"

@implementation AuthenticationService

- (instancetype)initPrivate {
    self = [super init];
    return self;
}

+ (AuthenticationService *)sharedInstance {
    static AuthenticationService* instance;
    static dispatch_once_t onceToken;
    @synchronized(self)
    {
        dispatch_once(&onceToken, ^{
            instance = [[AuthenticationService alloc] initPrivate];
        });
    }
    return instance;
}

- (void)useToken:(ADAuthenticationResult*)result
{
    // Do something with the token
    // Send token to resources such as graph
}

- (void)handleWrongUser
{
    // Show the user an error and give them another opportunity to sign in.
    [self acquireTokenForNewUser];
}

// Sign in a new user.
- (void)acquireTokenForNewUser
{
    ADUserIdentifier *adUserId = [ADUserIdentifier identifierWithId:_userId type:OptionalDisplayableId];
    
    ADAuthenticationError *error = nil;
    // Use the 'common' wildcard authority.  Later the app will need to record
    // what the wildcard authority actually resolved to.
    ADAuthenticationContext *context =
    [ADAuthenticationContext authenticationContextWithAuthority:_authority
                                              validateAuthority:true
                                                          error:&error];
    if (!context)
    {
        // Handle error.
        return;
    }
    
    // Save this and add it to any ADAL related app logging or diagnostics.
    context.correlationId = [NSUUID UUID];
    
    [context acquireTokenWithResource:_resource
                             clientId:_clientId
                          redirectUri:_redirectUri
                       promptBehavior:AD_PROMPT_ALWAYS
                               userId:adUserId.userId
                 extraQueryParameters:@"msafed=0"
                      completionBlock:^(ADAuthenticationResult *result)
     {
         self.authenticationResult = result;
         
         if (result.status == AD_USER_CANCELLED)
         {
             return;
         }
         
         if (result.status != AD_SUCCEEDED)
         {
             return;
         }
         
         // save the authority that was resolved during initial user sign-in
         _authority = result.tokenCacheItem.authority;
         
         // save the uniqueId so it can be used for future silent token acquisitions.
         _uniqueId = result.tokenCacheItem.userInformation.uniqueId;
         
         // update the userId with the actual userId entered by the user.
         _userId = result.tokenCacheItem.userInformation.userId;
         
         self.userLoggedIn = YES;
         
         [self useToken:result];
     }];
}

- (void)signoutUser
{
    @synchronized (self)
    {
        [self deleteCookies];
        [self clearTokens];
        
        self.userLoggedIn = NO;
        self.authenticationResult = nil;
    }
}

// Try to sign-in a user that was already signed in but whose session has
// been invalidated for some reason such as a changed password or expired
// refresh token.
- (void)acquireTokenOnInvalidGrant
{
    // Require the same user that was already signed in.
    ADUserIdentifier* adUserId = [ADUserIdentifier identifierWithId:_userId type:OptionalDisplayableId];
    
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context =
    [ADAuthenticationContext authenticationContextWithAuthority:_authority
                                              validateAuthority:true
                                                          error:&error];
    if (!context)
    {
        // Handle error.
        return;
    }
    
    // Save this and add it to any ADAL related app logging or diagnostics.
    context.correlationId = [NSUUID UUID];
    
    [context acquireTokenWithResource:_resource
                             clientId:_clientId
                          redirectUri:_redirectUri
                       promptBehavior:AD_PROMPT_ALWAYS
                               userId:adUserId.userId
                 extraQueryParameters:@"msafed=0"
                      completionBlock:^(ADAuthenticationResult *result)
     {
         self.authenticationResult = result;
         
         if (result.status == AD_USER_CANCELLED)
         {
             // Handle the fact that the user canceled the sign-in. Maybe show them an error and let them try again.
             return;
         }
         
         if (result.status != AD_SUCCEEDED)
         {
             return;
         }
         
         NSString* resultUniqueId = result.tokenCacheItem.userInformation.uniqueId;
         if ([_uniqueId caseInsensitiveCompare:resultUniqueId] != NSOrderedSame)
         {
             // The user did not sign in with the same user that was previously signed in.  Display an error and perhaps try again.
             [self handleWrongUser];
             return;
         }
         
         self.userLoggedIn = YES;
         
         [self useToken:result];
     }];
}

// Attempt to resolve an interaction required error.  If the cookies haven't yet expired in the
// web view then the user should not have to enter full creds again.  Instead, they may
// be able to go straight to MFA auth or consent.
- (void)acquireTokenInteractionRequired
{
    ADUserIdentifier* adUserId = [ADUserIdentifier identifierWithId:_userId type:OptionalDisplayableId];
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context =
    [ADAuthenticationContext authenticationContextWithAuthority:_authority
                                              validateAuthority:true
                                                          error:&error];
    
    if (!context)
    {
        // Handle error.
        return;
    }
    
    // Save this and add it to any ADAL related app logging or diagnostics.
    context.correlationId = [NSUUID UUID];
    
    [context acquireTokenWithResource:_resource
                             clientId:_clientId
                          redirectUri:_redirectUri
                       promptBehavior:AD_PROMPT_AUTO
                               userId:adUserId.userId
                 extraQueryParameters:@"msafed=0"
                      completionBlock:^(ADAuthenticationResult *result)
     {
         self.authenticationResult = result;
         
         if (result.status == AD_USER_CANCELLED)
         {
             // Handle the fact that the user canceled the sign-in. Maybe show them an error and let them try again.
             return;
         }
         
         if (result.status != AD_SUCCEEDED)
         {
             return;
         }
         
         NSString* resultUniqueId = result.tokenCacheItem.userInformation.uniqueId;
         if ([_uniqueId caseInsensitiveCompare:resultUniqueId] != NSOrderedSame)
         {
             // The user did not sign in with the same user that was previously signed in.  Display an error and perhaps try again.
             [self handleWrongUser];
             return;
         }
         
         self.userLoggedIn = YES;
         
         [self useToken:result];
     }];
}

- (void)acquireTokenSilent
{
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context =
    [ADAuthenticationContext authenticationContextWithAuthority:_authority
                                              validateAuthority:true
                                                          error:&error];
    
    if (!context)
    {
        // Handle error.
        return;
    }
    
    // Save this and add it to any ADAL related app logging or diagnostics.
    context.correlationId = [NSUUID UUID];
    
    ADUserIdentifier *adUserId = [ADUserIdentifier identifierWithId:_userId type:OptionalDisplayableId];
    [context acquireTokenSilentWithResource:_resource
                                   clientId:_clientId
                                redirectUri:_redirectUri
                                     userId:adUserId.userId
                            completionBlock:^(ADAuthenticationResult *result)
     {
         if (result.status != AD_SUCCEEDED)
         {
             self.authenticationResult = result;
             
             NSString* protocolCode = result.error.protocolCode;
             if (protocolCode != nil)
             {
                 if ([protocolCode isEqualToString:@"user_interaction_required"])
                 {
                     // Interaction required can happen any time the user is required to MFA for the first time.
                     [self acquireTokenInteractionRequired];
                 }
                 else if ([protocolCode isEqualToString:@"invalid_grant"])
                 {
                     [self acquireTokenOnInvalidGrant];
                 }
                 else
                 {
                     // Handle error
                 }
             }
             else if (result.error.code == AD_ERROR_SERVER_USER_INPUT_NEEDED)
             {
                 [self acquireTokenInteractionRequired];
             }
             return;
         }
         
         self.userLoggedIn = YES;
         
         [self useToken:result];
     }];
}

- (void)deleteCookies {
    NSHTTPCookieStorage *cookieStore = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    NSArray* cookies = cookieStore.cookies;
    for (NSHTTPCookie *cookie in cookies)
    {
        [cookieStore deleteCookie:cookie];
    }
}

- (void)clearTokens {
    [[ADKeychainTokenCache defaultKeychainCache] removeAllForUserId:_userId
                                                           clientId:_clientId
                                                              error:nil];
}

@end
