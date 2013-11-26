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

#import "ADALiOS.h"
#import "ADAuthenticationContext.h"
#import "ADDefaultTokenCacheStore.h"
#import "ADAuthenticationResult+Internal.h"
#import "IPAuthenticationContext.h"
#import "IPAuthenticationResult.h"
#import "IPAuthorization.h"
#import "IPAuthenticationSettings.h"

NSString* const multiUserError = @"The token cache store for this resource contain more than one user. Please set the 'userId' parameter to determine which one to be used.";
NSString* const unknownError = @"Uknown error.";
NSString* const credentialsNeeded = @"The user credentials are need to obtain access token. Please call acquireToken with 'promptBehavior' not set to AD_PROMPT_NEVER";

@implementation ADAuthenticationContext

-(id) init
{
    //Ensure that the appropriate init function is called. This will cause the runtime to throw.
    [super doesNotRecognizeSelector:_cmd];
    return nil;
}

+(NSString*) canonicalizeAuthority: (NSString*) authority
{
    if ([NSString isStringNilOrBlank:authority])
    {
        return nil;
    }
    
    NSString* trimmed = [[authority trimmedString] lowercaseString];
    if (![trimmed hasSuffix:@"/"])
    {
        trimmed = [trimmed stringByAppendingString:@"/"];
    }

    NSURL* url = [NSURL URLWithString:trimmed];
    
    if (!url)
    {
        NSString* message = [NSString stringWithFormat:@"Authority %@", authority];
        AD_LOG_WARN(@"The authority is not a valid URL", message);
        return nil;
    }
    NSString* scheme = url.scheme;
    if (![scheme isEqualToString:@"https"])
    {
        NSString* message = [NSString stringWithFormat:@"Authority %@", authority];
        AD_LOG_WARN(@"Non HTTPS protocol for the authority", message);
        return nil;
    }

    return trimmed;
}

-(id) initInternalWithAuthority: (NSString*) authority
              validateAuthority: (BOOL)bValidate
                tokenCacheStore: (id<ADTokenCacheStoring>)tokenCache
                          error: (ADAuthenticationError* __autoreleasing *) error
{
    NSString* extractedAuthority = [self.class canonicalizeAuthority:authority];
    RETURN_ON_INVALID_ARGUMENT(!extractedAuthority, authority, nil);
  
    self = [super init];
    if (self)
    {
        _authority = extractedAuthority;
        _validateAuthority = bValidate;
        _tokenCacheStore = tokenCache;
    }
    return self;
}


+(ADAuthenticationContext*) contextWithAuthority: (NSString*) authority
                                           error: (ADAuthenticationError* __autoreleasing *) error
{
    API_ENTRY;
    return [self contextWithAuthority: authority
                    validateAuthority: YES
                      tokenCacheStore: [ADDefaultTokenCacheStore sharedInstance]
                                error: error];
}

+(ADAuthenticationContext*) contextWithAuthority: (NSString*) authority
                               validateAuthority: (BOOL) bValidate
                                           error: (ADAuthenticationError* __autoreleasing *) error
{
    API_ENTRY
    return [self contextWithAuthority: authority
                    validateAuthority: bValidate
                      tokenCacheStore: [ADDefaultTokenCacheStore sharedInstance]
                                error: error];
}

+(ADAuthenticationContext*) contextWithAuthority: (NSString*) authority
                                 tokenCacheStore: (id<ADTokenCacheStoring>) tokenCache
                                           error: (ADAuthenticationError* __autoreleasing *) error
{
    API_ENTRY;
    return [self contextWithAuthority:authority
                    validateAuthority:YES
                      tokenCacheStore:tokenCache
                                error:error];
}

+(ADAuthenticationContext*) contextWithAuthority: (NSString*) authority
                               validateAuthority: (BOOL)bValidate
                                 tokenCacheStore: (id<ADTokenCacheStoring>)tokenCache
                                           error: (ADAuthenticationError* __autoreleasing *) error
{
    API_ENTRY;
    RETURN_NIL_ON_NIL_EMPTY_ARGUMENT(authority);
    
    ADAuthenticationContext* context = [self alloc];
    if (context)
    {
        return [context initInternalWithAuthority: authority
                                validateAuthority: bValidate
                                  tokenCacheStore: tokenCache
                                            error: error];
    }
    return context;
}


-(void) acquireToken: (NSString*) resource
            clientId: (NSString*) clientId
         redirectUri: (NSURL*) redirectUri
     completionBlock: (ADAuthenticationCallback) completionBlock
{
    API_ENTRY;
    return [self acquireToken:resource
                                clientId:clientId
                             redirectUri:redirectUri
                          promptBehavior:AD_PROMPT_AUTO
                                  userId:nil
                    extraQueryParameters:nil
                         completionBlock:completionBlock];
}

-(void) acquireToken: (NSString*) resource
            clientId: (NSString*) clientId
         redirectUri: (NSURL*) redirectUri
              userId: (NSString*) userId
     completionBlock: (ADAuthenticationCallback) completionBlock
{
    API_ENTRY;
    [self acquireToken:resource
                         clientId:clientId
                      redirectUri:redirectUri
                   promptBehavior:AD_PROMPT_AUTO
                           userId:userId
             extraQueryParameters:nil
                  completionBlock:completionBlock];
}


-(void) acquireToken: (NSString*) resource
            clientId: (NSString*)clientId
         redirectUri: (NSURL*) redirectUri
              userId: (NSString*) userId
extraQueryParameters: (NSString*) queryParams
     completionBlock: (ADAuthenticationCallback) completionBlock
{
    API_ENTRY;
    [self acquireToken:resource
                         clientId:clientId
                      redirectUri:redirectUri
                   promptBehavior:AD_PROMPT_AUTO
                           userId:userId
             extraQueryParameters:queryParams
                  completionBlock:completionBlock];
}

/*Attemps to use the cache. Returns YES if an attempt was successful or if an
 internal asynchronous call will proceed the processing */
-(BOOL) tryRefreshingFromCacheItem: (ADTokenCacheStoreItem*) item
                               key: (ADTokenCacheStoreKey*) key
                          resource: (NSString*) resource
                          clientId: (NSString*) clientId
                       redirectUri: (NSURL*) redirectUri
                    promptBehavior: (ADPromptBehavior) promptBehavior
                            userId: (NSString*) userId
              extraQueryParameters: (NSString*) queryParams
                   completionBlock: (ADAuthenticationCallback)completionBlock
{
    THROW_ON_NIL_ARGUMENT(item);//Should be set in this internal call
    
    if (!item.isExpired)
    {
        //We have an cache item that can be used directly:
        ADAuthenticationResult* result = [ADAuthenticationResult resultFromTokenCacheStoreItem:item];
        completionBlock(result);
        return YES;
    }
    
    if (![NSString isStringNilOrBlank:item.refreshToken])
    {
        //Expired, but we can use a refresh token:
        [self internalAcquireTokenByRefreshToken:item.refreshToken
                                        clientId:clientId
                                        resource:resource
                                    storeInCache:YES
                                 completionBlock:^(ADAuthenticationResult *result) {
            //The code in the block will execute asynchronously:
            ADAuthenticationResult* resultToUse = result;
            if (nil == resultToUse)
            {
                //Shouldn't happen, but the error is recoverable:
                ADAuthenticationError* error = [ADAuthenticationError unexpectedInternalError:@"Authorization callback called with 'nil' result by acquireTokenByRefreshToken:clientId:resource:completionBlock."];
                resultToUse = [ADAuthenticationResult resultFromError:error];
            }
            
            if (resultToUse.error && AD_ERROR_INVALID_REFRESH_TOKEN != resultToUse.error.code)
            {
                //The access token has expired and the refresh token is invalid.
                //Remove the cache item and call recursively acquireToken to
                //reauthenticate the user:
                [self.tokenCacheStore removeItemWithKey:key userId:userId];
                
                [self acquireToken: resource
                                     clientId: clientId
                                  redirectUri: redirectUri
                               promptBehavior: promptBehavior
                                       userId: userId
                         extraQueryParameters: queryParams
                              completionBlock: completionBlock];
                
                return;//Make sure that the completion block is not called, as the acquireToken above will call it.
            }
            
            if (resultToUse.status != AD_SUCCEEDED && nil == resultToUse.error)
            {
                //The result failed without providing an error object. This is a internal error condition:
                ADAuthenticationError* error =
                    [ADAuthenticationError unexpectedInternalError:@"acquireTokenByRefreshToken returned without success and 'nil' error object."];
                resultToUse = [ADAuthenticationResult resultFromError:error];
            }
            
            //The mandatory completion block callback:
            completionBlock(resultToUse);
        }];//End of the refreshing token completion block, executed asynchronously.
        return YES;//The asynchronous block handles the next steps.
    }
    //Item present, but cannot be used, remove it from the cache:
    [self.tokenCacheStore removeItemWithKey:key userId:item.userInformation.userId];
    return NO;//The function couldn't attempt to use the cache asynchronously or directly.
}

//Handle
-(void) ipalAuthenticationCallback: (IPAuthenticationResult*) ipalResult
                          clientId: (NSString*) clientId
                      storeInCache: (BOOL) storeInCache
                   completionBlock: (ADAuthenticationCallback) completionBlock
{
    ADAuthenticationResult* toReturn = nil;
    ADAuthenticationError* error;
    if (!ipalResult)
    {
        error = [ADAuthenticationError unexpectedInternalError:@"IPAL Authorization callback called with 'nil' result."];
    }
    else if (AuthenticationCancelled == ipalResult.status)
    {
        toReturn = [ADAuthenticationResult resultFromCancellation];
    }
    else if (AuthenticationFailed == ipalResult.status)
    {
        NSString* errorDescription = ipalResult.errorDescription;
        if ([NSString isStringNilOrBlank:errorDescription])
        {
            errorDescription = unknownError;
        }
        error = [ADAuthenticationError errorFromAuthenticationError: AD_ERROR_AUTHENTICATION
                                                       protocolCode: ipalResult.error
                                                       errorDetails: errorDescription];
    }
    else if (AuthenticationSucceeded == ipalResult.status)
    {
        if (!ipalResult.authorization)
        {
            error = [ADAuthenticationError unexpectedInternalError:@"Valid authorization is expected on success."];
        }
        else
        {
            ADTokenCacheStoreItem* item = [[ADTokenCacheStoreItem alloc] init];
            
            item.authority = self.authority;
            item.resource = ipalResult.authorization.resource;
            item.clientId = clientId;
            item.accessToken = ipalResult.authorization.accessToken;
            item.accessTokenType = ipalResult.authorization.accessTokenType;
            item.refreshToken = ipalResult.authorization.refreshToken;
            item.expiresOn = ipalResult.authorization.expires;
            item.userInformation = nil;
            item.tenantId = nil;
            if (storeInCache && self.tokenCacheStore)
            {
                //Attemp to write and ignore cache errors. Cache errors will be logged automatically.
                [self.tokenCacheStore addOrUpdateItem:item error:nil];
            }
            toReturn = [ADAuthenticationResult resultFromTokenCacheStoreItem:item];
        }
    }
    else
    {
        error = [ADAuthenticationError unexpectedInternalError:@"Unknown status value."];
    }
    
    //Now call the callback appropriately:
    if (error)
    {
        toReturn = [ADAuthenticationResult resultFromError:error];
    }
    completionBlock(toReturn);
}

-(void) acquireToken: (NSString*) resource
            clientId: (NSString*) clientId
         redirectUri: (NSURL*) redirectUri
      promptBehavior: (ADPromptBehavior) promptBehavior
              userId: (NSString*) userId
extraQueryParameters: (NSString*) queryParams
     completionBlock: (ADAuthenticationCallback)completionBlock
{
    API_ENTRY;
    THROW_ON_NIL_ARGUMENT(completionBlock);
    
    //Check the cache:
    ADAuthenticationError* error;
    //We are explicitly creating a key first to ensure indirectly that all of the required arguments are correct.
    //This is the safest way to guarantee it:
    ADTokenCacheStoreKey* key = [ADTokenCacheStoreKey keyWithAuthority:self.authority resource:resource clientId:clientId error:&error];
    if (!key)
    {
        //If the key cannot be extracted, call the callback with the information:
        ADAuthenticationResult* result = [ADAuthenticationResult resultFromError:error];
        completionBlock(result);
        return;
    }
    
    if (promptBehavior != AD_PROMPT_ALWAYS && self.tokenCacheStore)
    {
        //Cache should be used in this case:
        ADTokenCacheStoreItem* item = nil;
        if (!userId)
        {
            //Null passed, check the cache for tokens for all users:
            NSArray* items = [self.tokenCacheStore getItemsWithKey:key];
            if (items.count > 1)
            {
                //More than one user token available in the cache, raise error to tell the developer to denote the desired user:
                ADAuthenticationError* error  = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_MULTIPLE_USERS
                                                                                       protocolCode:nil
                                                                                       errorDetails:multiUserError];
                completionBlock([ADAuthenticationResult resultFromError:error]);
                return;
            }
            else if (items.count == 1)
            {
                item = [items objectAtIndex:0];//Exactly one - just use it.
            }
        }
        else
        {
            item = [self.tokenCacheStore getItemWithKey:key userId:userId];//Pass the userId to the cache if supplied
        }
        
        if (nil != item)
        {
            //Found something in the cache, try using it:
            if ([self tryRefreshingFromCacheItem:item
                                             key:key
                                        resource:resource
                                        clientId:clientId
                                     redirectUri:redirectUri
                                  promptBehavior:promptBehavior
                                          userId:userId
                            extraQueryParameters:queryParams
                                 completionBlock:completionBlock])
            {
                return; //The tryRefreshingFromCacheItem has taken care of the token obtaining
            }
        }
    }
    
    if (promptBehavior == AD_PROMPT_NEVER)
    {
        //The cache lookup and refresh token attempt have been unsuccessful,
        //so credentials are neede to get an access token:
        ADAuthenticationError* error =
            [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_USER_INPUT_NEEDED
                                                   protocolCode:nil
                                                   errorDetails:credentialsNeeded];
        ADAuthenticationResult* result = [ADAuthenticationResult resultFromError:error];
        completionBlock(result);
        return;
    }
    
    //The rest of the authorization code will need to execute on the main thread
    //The asynchronous execution guarantees it:
    dispatch_async(dispatch_get_main_queue(), ^{
        [IPAuthenticationContext settings].clientId = clientId;
        NSString* redirectUriString = redirectUri.absoluteString;
        [IPAuthenticationContext settings].redirectUri = redirectUriString;
        [IPAuthenticationContext requestAuthorization:self.authority
                                             resource:resource
                                                scope:nil
                                           completion:^(IPAuthenticationResult *result)
        {
            [self ipalAuthenticationCallback:result clientId:clientId storeInCache:YES completionBlock:completionBlock];
        }];
    });
}

-(void) acquireTokenByRefreshToken: (NSString*)refreshToken
                          clientId: (NSString*)clientId
                   completionBlock: (ADAuthenticationCallback)completionBlock
{
    API_ENTRY;
    NOT_IMPLEMENTED;//Note that the implementation does not support lack of "resource" in the call yet.
    [self internalAcquireTokenByRefreshToken:refreshToken
                                    clientId:clientId
                                    resource:nil
                                storeInCache:NO
                             completionBlock:completionBlock];
}

-(void) acquireTokenByRefreshToken:(NSString*)refreshToken
                          clientId:(NSString*)clientId
                          resource:(NSString*)resource
                   completionBlock:(ADAuthenticationCallback)completionBlock
{
    API_ENTRY;
    [self internalAcquireTokenByRefreshToken:refreshToken
                                    clientId:clientId
                                    resource:resource
                                storeInCache:NO
                             completionBlock:completionBlock];

}

-(void) internalAcquireTokenByRefreshToken:(NSString*)refreshToken
                                  clientId:(NSString*)clientId
                                  resource:(NSString*)resource
                              storeInCache: (BOOL) storeInCache
                           completionBlock:(ADAuthenticationCallback)completionBlock
{
    //Temporarily avoid crashing:
    [IPAuthenticationContext settings].clientId = clientId;
    IPAuthorization* authorization = [[IPAuthorization alloc] initWithServer:self.authority resource:resource scope:nil];
    authorization.refreshToken = refreshToken;
    
    //The IPAL methods work only in the main thread:
    dispatch_async(dispatch_get_main_queue(), ^
    {
        [IPAuthenticationContext refreshAuthorization:authorization completion:^(IPAuthenticationResult *result)
         {
             [self ipalAuthenticationCallback:result clientId:clientId storeInCache:storeInCache completionBlock:completionBlock];
         }];
    });
}


@end

