// Created by Boris Vidolov on 11/6/13.
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
#import "ADAuthenticationResult+Internal.h"
#import "ADTokenCacheStoreItem.h"

NSString* const cancelError = @"The user has cancelled the authorization.";

@implementation ADAuthenticationResult (Internal)

-(id) initWithCancellation
{
    ADAuthenticationError* error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_USER_CANCEL
                                                                          protocolCode:nil
                                                                          errorDetails:cancelError];
    return [self initWithError:error status:AD_USER_CANCELLED correlationId:nil];
}

-(id) initWithItem: (ADTokenCacheStoreItem*) item
multiResourceRefreshToken: (BOOL) multiResourceRefreshToken
     correlationId: (NSUUID*) correlationId
{
    self = [super init];
    if (self)
    {
        _status = AD_SUCCEEDED;
        _tokenCacheStoreItem = item;
        _multiResourceRefreshToken = multiResourceRefreshToken;
        _correlationId = correlationId;
    }
    return self;
}

-(id) initWithError: (ADAuthenticationError*)error
             status: (ADAuthenticationResultStatus) status
      correlationId: (NSUUID*) correlationId
{
    THROW_ON_NIL_ARGUMENT(error);
    
    self = [super init];
    if (self)
    {
        _status = status;
        _error = error;
        _correlationId = correlationId;
    }
    return self;
}

/*! Creates an instance of the result from the cache store. */
+(ADAuthenticationResult*) resultFromTokenCacheStoreItem: (ADTokenCacheStoreItem*) item
                               multiResourceRefreshToken: (BOOL) multiResourceRefreshToken
                                           correlationId: (NSUUID*) correlationId
{
    if (item)
    {
        ADAuthenticationError* error;
        [item extractKeyWithError:&error];
        if (error)
        {
            //Bad item, return error:
            return [ADAuthenticationResult resultFromError:error correlationId:correlationId];
        }
        if ([NSString isStringNilOrBlank:item.accessToken])
        {
            //Bad item, the access token should be accurate, else an error should be
            //reported instead of this creator:
            ADAuthenticationError* error = [ADAuthenticationError unexpectedInternalError:@"ADAuthenticationResult created from item with no access token."];
            return [ADAuthenticationResult resultFromError:error correlationId:correlationId];
        }
        //The item can be used, just use it:
        return [[ADAuthenticationResult alloc] initWithItem:item multiResourceRefreshToken:multiResourceRefreshToken correlationId:correlationId];
    }
    else
    {
        ADAuthenticationError* error = [ADAuthenticationError unexpectedInternalError:@"ADAuthenticationResult created from nil token item."];
        return [ADAuthenticationResult resultFromError:error correlationId:correlationId];
    }
}

+(ADAuthenticationResult*) resultFromError: (ADAuthenticationError*) error
                             correlationId: (NSUUID*) correlationId;
{
    ADAuthenticationResult* result = [ADAuthenticationResult alloc];
    return [result initWithError:error status:AD_FAILED correlationId:correlationId];
}

+(ADAuthenticationResult*) resultFromCancellation
{
    ADAuthenticationResult* result = [ADAuthenticationResult alloc];
    return [result initWithCancellation];
}

@end
