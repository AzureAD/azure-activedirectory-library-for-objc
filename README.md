#Windows Azure Active Directory Authentication Library (ADAL) for iOS
=====================================

[![Build Status](https://travis-ci.org/MSOpenTech/azure-activedirectory-library-for-ios.png)](https://travis-ci.org/MSOpenTech/azure-activedirectory-library-for-ios)
[![Coverage Status](https://coveralls.io/repos/MSOpenTech/azure-activedirectory-library-for-ios/badge.png)](https://coveralls.io/r/MSOpenTech/azure-activedirectory-library-for-ios) 

The ADAL SDK for iOS gives you the ability to add Windows Azure Active Directory authentication to your application with just a few lines of additional code. Using our ADAL SDKs you can quickly and easily extend your existing application to all the employees that use Windows Azure AD and Active Directory on-premises using Active Directory Federation Services, including Office365 customers. This SDK gives your application the full functionality of Windows Azure AD, including industry standard protocol support for OAuth2, Web API integration, and two factor authentication support. Best of all, it’s FOSS (Free and Open Source Software) so that you can participate in the development process as we build these libraries.

[Refer to our Wiki](https://github.com/MSOpenTech/azure-activedirectory-library-for-ios/wiki) for detailed walkthroughs on how to use this package including accessing a node.js REST API interface secured by Windows Azure Active Directory using the ADAL for iOS.

## Latest Preview Release

We have released a Preview of the ADAL for iOS! [You can grab the release here] (https://github.com/MSOpenTech/azure-activedirectory-library-for-ios/releases/tag/0.5-alpha)

## Quick Start

1. Clone the repository to your machine
2. Build the library
3. Add the ADALiOS library to your project
4. Add ADALiOSFramework to “Target Dependences” build phase of your application
5. Add ADALiOSBundle.bundle to “Copy Bundle Resources” build phase of your application
6. Add libADALiOS to “Link With Libraries” phase.

## Usage

### ADAuthenticationContext

The starting point for the API is in ADAuthenticationContext.h header. ADAuthenticationContext is the main class used for obtaining, caching and supplying access tokens.

#### How to quickly get a token from the SDK:

```Objective-C
	ADAuthenticationContext* authContext;

	+(void) getToken : (BOOL) clearCache completionHandler:(void (^) (NSString*))completionBlock;
	{
    ADAuthenticationError *error __autoreleasing;
    authContext = [ADAuthenticationContext authenticationContextWithAuthority:authority error:&error];
    
    NSURL *redirectUri = [[NSURL alloc]initWithString:redirectUriString];
    
    if(clearCache)
    {
        [authContext.tokenCacheStore removeAll];
    }
    authContext.validateAuthority = NO;
    [authContext acquireTokenWithResource:resourceId clientId:clientId redirectUri:redirectUri completionBlock:^(ADAuthenticationResult *result) {
        
        if (result == nil)
        {
            // display error on the screen
        }
        else
        {
            completionBlock(result.tokenCacheStoreItem.accessToken);
        }
    } 
    ]; }
```

#### Adding the Token to the authHeader to acess APIs:

```Objective-C

	+(NSArray*) getTodoList:(id)delegate
	{
    __block NSMutableArray *scenarioList = nil;
    
    [self getToken:YES completionHandler:^(NSString* accessToken){
    
    NSURL *todoRestApiURL = [[NSURL alloc]initWithString:todoRestApiUrlString];
            
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc]initWithURL:todoRestApiURL];
            
    NSString *authHeader = [NSString stringWithFormat:@"Bearer %@", accessToken];
            
    [request addValue:authHeader forHTTPHeaderField:@"Authorization"];
            
    NSOperationQueue *queue = [[NSOperationQueue alloc]init];
            
    [NSURLConnection sendAsynchronousRequest:request queue:queue completionHandler:^(NSURLResponse *response, NSData *data, NSError *error) {
                
            if (error == nil){
                    
            NSArray *scenarios = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
                
            todoList = [[NSMutableArray alloc]init];
                    
            //each object is a key value pair
            NSDictionary *keyVauePairs;
                    
            for(int i =0; i < todo.count; i++)
            {
                keyVauePairs = [todo objectAtIndex:i];
                        
                Task *s = [[Task alloc]init];
                        
                s.id = (NSInteger)[keyVauePairs objectForKey:@"TaskId"];
                s.description = [keyVauePairs objectForKey:@"TaskDescr"];
                
                [todoList addObject:s];
                
             }
                
            }
        
        [delegate updateTodoList:TodoList];
        
        }];
        
    }];
    return nil; } 
    
```

## License

Copyright (c) Microsoft Open Technologies, Inc.  All rights reserved. Licensed under the Apache License, Version 2.0 (the "License"); 
