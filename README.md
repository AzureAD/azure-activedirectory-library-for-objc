#Windows Azure Active Directory Authentication Library (ADAL) Universal build for OSX
=====================================

## This is the ADAL OSX Universal branch

This Branch builds ADAL for OSX as a Universal binary that supports 32bit and 64bit usage WITHOUT Automatic Reference Counting. Note that only the core ADAL library is built as Universal, the ADAL unit tests build as x86_64 and required ARC so do not
attempt to build or run the unit tests in 32bit mode.

## Latest Preview Release

We have released a Preview of the ADAL for iOS! [You can grab the release here] (https://github.com/MSOpenTech/azure-activedirectory-library-for-ios/releases/tag/0.5-alpha)

## Quick Start

1. Clone the repository to your machine
2. Build the library
3. Add the ADALiOS library to your project
4. Add the storyboards from the ADALiOSBundle to your project resources
5. Add libADALiOS to “Link With Libraries” phase. 

### With Cocoapods
    pod 'ADALiOS', '~> 0.5.1-alpha'

## Usage

### ADAuthenticationContext

The starting point for the API is in ADAuthenticationContext.h header. ADAuthenticationContext is the main class used for obtaining, caching and supplying access tokens.

#### How to quickly get a token from the SDK:

```Objective-C
	ADAuthenticationContext* authContext;
	NSString* authority;
	NSString* redirectUriString;
	NSString* resourceId;
	NSString* clientId;

+(void) getToken : (BOOL) clearCache completionHandler:(void (^) (NSString*))completionBlock;
{
    ADAuthenticationError *error;
    authContext = [ADAuthenticationContext authenticationContextWithAuthority:authority
                                                                        error:&error];
    
    NSURL *redirectUri = [NSURL URLWithString:redirectUriString];
    
    if(clearCache){
        [authContext.tokenCacheStore removeAll];
    }
    
    [authContext acquireTokenWithResource:resourceId
                                 clientId:clientId
                              redirectUri:redirectUri
                          completionBlock:^(ADAuthenticationResult *result) {
        if (AD_SUCCEEDED != result.status){
            // display error on the screen
            [self showError:result.error.errorDetails];
        }
        else{
            completionBlock(result.accessToken);
        }
    }];
}
```

#### Adding the Token to the authHeader to access APIs:

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
##Common problems

**Application, using the ADAL library crashes with the following exception:**<br/> *** Terminating app due to uncaught exception 'NSInvalidArgumentException', reason: '+[NSString isStringNilOrBlank:]: unrecognized selector sent to class 0x13dc800'<br/>
**Solution:** Make sure that you add the -ObjC flag to "Other Linker Flags" build setting of the application. For more information, see Apple documentation for using static libraries:<br/> https://developer.apple.com/library/ios/technotes/iOSStaticLibraries/Articles/configuration.html#//apple_ref/doc/uid/TP40012554-CH3-SW1.

## License

Copyright (c) Microsoft Open Technologies, Inc.  All rights reserved. Licensed under the Apache License, Version 2.0 (the "License"); 
