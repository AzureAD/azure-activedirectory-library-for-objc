
#Microsoft Azure Active Directory Authentication Library (ADAL) for iOS and OSX
=====================================

####NOTE regarding iOS 9

Apple has released iOS 9 which includes support for App Transport Security (ATS). ATS restricts apps from accessing the internet unless they meet several security requirements including TLS 1.2 and SHA-256. While Microsoft's APIs support these standards some third party APIs and content delivery networks we use have yet to be upgraded. This means that any app that relies on Azure Active Directory or Microsoft Accounts will fail when compiled with iOS 9. For now our recommendation is to disable ATS, which reverts to iOS 8 functionality. Please refer to the [documentation on the NSAppTransport info.plist key](https://developer.apple.com/library/ios/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/uid/TP40009251-SW33) for more information.

----


[![Build Status](https://travis-ci.org/AzureAD/azure-activedirectory-library-for-objc.svg?branch=1.2.x)](https://travis-ci.org/AzureAD/azure-activedirectory-library-for-objc)

The ADAL SDK for iOS and Mac OS X gives you the ability to add support for Work Accounts to your application with just a few lines of additional code. This SDK gives your application the full functionality of Microsoft Azure AD, including industry standard protocol support for OAuth2, Web API integration with user level consent, and two factor authentication support. Best of all, it’s FOSS (Free and Open Source Software) so that you can participate in the development process as we build these libraries. 

## Contribution History

[![Stories in Ready](https://badge.waffle.io/AzureAD/azure-activedirectory-library-for-objc.png?label=ready&title=Ready)](https://waffle.io/AzureAD/azure-activedirectory-library-for-objc)

[![Throughput Graph](https://graphs.waffle.io/AzureAD/azure-activedirectory-library-for-objc/throughput.svg)](https://waffle.io/AzureAD/azure-activedirectory-library-for-objc/metrics)

## Samples and Documentation

[We provide a full suite of sample applications and documentation on GitHub](https://github.com/AzureADSamples) to help you get started with learning the Azure Identity system. This includes tutorials for native clients such as Windows, Windows Phone, iOS, OSX, Android, and Linux. We also provide full walkthroughs for authentication flows such as OAuth2, OpenID Connect, Graph API, and other awesome features. 

Visit your Azure Identity samples for iOS is here: [https://github.com/AzureADSamples/NativeClient-iOS](https://github.com/AzureADSamples/NativeClient-iOS)

## Community Help and Support

We leverage [Stack Overflow](http://stackoverflow.com/) to work with the community on supporting Azure Active Directory and its SDKs, including this one! We highly recommend you ask your questions on Stack Overflow (we're all on there!) Also browser existing issues to see if someone has had your question before. 

We recommend you use the "adal" tag so we can see it! Here is the latest Q&A on Stack Overflow for ADAL: [http://stackoverflow.com/questions/tagged/adal](http://stackoverflow.com/questions/tagged/adal)

## Contributing

All code is licensed under the MIT license and we triage actively on GitHub. We enthusiastically welcome contributions and feedback. You can clone the repo and start contributing now. 

## Quick Start

1. Clone the repository to your machine
2. Build the library
3. Add the ADALiOS library to your project
4. Add the storyboards from the ADALiOSBundle to your project resources
5. Add libADALiOS to “Link With Libraries” phase. 


##Download

We've made it easy for you to have multiple options to use this library in your iOS project:

###Option 1: Source Zip

To download a copy of the source code, click "Download ZIP" on the right side of the page or click [here](https://github.com/AzureAD/azure-activedirectory-library-for-objc/archive/1.2.5.tar.gz).

###Option 2: Cocoapods

    pod 'ADALiOS', '~> 1.2.5'

## Usage

### Set up Keychain Sharing Entitlements in your Xcode Project ###

Click on your project in the Navigator pane in Xcode. Click on your application target and
then the "Capabilities" tab. Scroll down to "Keychain Sharing" and flip the switch on. Add
"com.microsoft.adalcache" to that list.

Alternatively you can disable keychain sharing by setting the keychain sharing group to
your application's bundle id.

```Objective-C
    [[ADAuthenticationSettings sharedInstance] setSharedCacheKeychainGroup:@"<your.bundle.id.here>"];
```

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

### Diagnostics


#### Logs

ADAL relies heavily on logging to diagnose issues. It is highly recommended that you set
an ADAL logging callback and provide a way for users to submit logs when they are having
authentication issues. 

##### Logging Callback

You can set a callback to capture ADAL logging and incorporate it in your own application's
logging:

```Objective-C
    [ADLogger setLogCallBack:^(ADAL_LOG_LEVEL logLevel, NSString *message, NSString *additionalInformation, NSInteger errorCode) {
        //HANDLE LOG MESSAGE HERE
    }]
```

Otherwise ADAL outputs to NSLog by default, which will print messages on the console.

##### Example Log Message

The message portion of ADAL iOS are in the format of ADALiOS [timestamp - correlation_id] message

```
ADALiOS [2015-06-22 19:42:53 - 1030CB25-798F-4A6F-97DF-04A3A3E9DFF2] ADAL API call [Version - 1.2.5]
```

Providing correlation IDs and timestamps are tremendously in tracking down issues. The only
reliable place to retrieve them is from ADAL logging.


##### Logging Levels

+ ADAL_LOG_LEVEL_NO_LOG (Disable all logging)
+ ADAL_LOG_LEVEL_ERROR (Default level, prints out information only when errors occur)
+ ADAL_LOG_LEVEL_WARNING (Warning)
+ ADAL_LOG_LEVEL_INFO (Library entry points, with parameters and various keychain operations)
+ ADAL_LOG_LEVEL_Verbose (API tracing )


To set the logging level in your application call +[ADLogger setLevel:]

```Objective-C
[ADLogger setLevel:ADAL_LOG_LEVEL_INFO]
 ```
 
#### Network Traces

You can use various tools to capture the HTTP traffic that ADAL generates.  This is most
useful if you are familiar with the OAuth protocol or if you need to provide diagnostic
information to Microsoft or other support channels.

Charles is the easiest HTTP tracing tool in OSX.  Use the following links to setup it up
to correctly record ADAL network traffic.  In order to be useful it is necessary to
configure Charles, to record unencrypted SSL traffic.  NOTE: Traces generated in this way
may contain highly privileged information such as access tokens, usernames and passwords.  
If you are using production accounts, do not share these traces with 3rd parties. 
If you need to supply a trace to someone in order to get support, reproduce the issue with
a temporary account with usernames and passwords that you don't mind sharing.

+ [Setting Up SSL For iOS Simulator or Devices](http://www.charlesproxy.com/documentation/faqs/ssl-connections-from-within-iphone-applications/)

#### ADAuthenticationError

ADAuthenticationErrors are provided in all callbacks in the ADAuthenticationResult's error
property when an error occurs. They can be used to have the application display more
more informative errors to the user, however ADAL Error messages are not localized. All
ADAuthenticationErrors are logged with the ADAL logger as well.

##Common problems

**Application, using the ADAL library crashes with the following exception:**<br/> 
*** Terminating app due to uncaught exception 'NSInvalidArgumentException', reason: '+[NSString isStringNilOrBlank:]: unrecognized selector sent to class 0x13dc800'<br/>

**Solution:** Make sure that you add the -ObjC flag to "Other Linker Flags" build setting
of the application. For more information, see Apple documentation for using static
libraries:<br/> https://developer.apple.com/library/ios/technotes/iOSStaticLibraries/Articles/configuration.html#//apple_ref/doc/uid/TP40012554-CH3-SW1.

**Log ins are not persisting, Cache always returns empty**<br/>

**Solution:** Either add the "com.microsoft.adalcache" keychain sharing entitlement to
your application, or disable keychain sharing by passing in your application's bundle id
in ADAuthenticationSettings:

```Objective-C
    [[ADAuthenticationSettings sharedInstance] setSharedCacheKeychainGroup:@"<your.bundle.id.here>"];
```

## License

Copyright (c) Microsoft Open Technologies, Inc.  All rights reserved. Licensed under the Apache License, Version 2.0 (the "License"); 
