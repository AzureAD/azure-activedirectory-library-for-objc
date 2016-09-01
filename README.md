
#Microsoft Azure Active Directory Authentication Library (ADAL) for iOS and OSX
=====================================

[![Build Status](https://travis-ci.org/AzureAD/azure-activedirectory-library-for-objc.svg?branch=1.2.x)](https://travis-ci.org/AzureAD/azure-activedirectory-library-for-objc)

The ADAL SDK for iOS and Mac OS X gives you the ability to add support for Work Accounts to your application with just a few lines of additional code. This SDK gives your application the full functionality of Microsoft Azure AD, including industry standard protocol support for OAuth2, Web API integration with user level consent, and two factor authentication support. Best of all, it’s FOSS (Free and Open Source Software) so that you can participate in the development process as we build these libraries. 

## Contribution History

[![Stories in Ready](https://badge.waffle.io/AzureAD/azure-activedirectory-library-for-objc.png?label=ready&title=Ready)](https://waffle.io/AzureAD/azure-activedirectory-library-for-objc)

[![Throughput Graph](https://graphs.waffle.io/AzureAD/azure-activedirectory-library-for-objc/throughput.svg)](https://waffle.io/AzureAD/azure-activedirectory-library-for-objc/metrics)

## Samples and Documentation

[We provide a full suite of sample applications and documentation on GitHub](https://github.com/AzureADSamples) to help you get started with learning the Azure Identity system. This includes tutorials for native clients such as Windows, Windows Phone, iOS, OSX, Android, and Linux. We also provide full walkthroughs for authentication flows such as OAuth2, OpenID Connect, Graph API, and other awesome features. 

Azure Identity samples for iOS is here: [https://github.com/AzureADSamples/NativeClient-iOS](https://github.com/AzureADSamples/NativeClient-iOS)

## Community Help and Support

We leverage [Stack Overflow](http://stackoverflow.com/) to work with the community on supporting Azure Active Directory and its SDKs, including this one! We highly recommend you ask your questions on Stack Overflow (we're all on there!) Also browser existing issues to see if someone has had your question before. 

We recommend you use the "adal" tag so we can see it! Here is the latest Q&A on Stack Overflow for ADAL: [http://stackoverflow.com/questions/tagged/adal](http://stackoverflow.com/questions/tagged/adal)

## Security Reporting

If you find a security issue with our libraries or services please report it to [secure@microsoft.com](mailto:secure@microsoft.com) with as much detail as possible. Your submission may be eligible for a bounty through the [Microsoft Bounty](http://aka.ms/bugbounty) program. Please do not post security issues to GitHub Issues or any other public site. We will contact you shortly upon receiving the information. We encourage you to get notifications of when security incidents occur by visiting [this page](https://technet.microsoft.com/en-us/security/dd252948) and subscribing to Security Advisory Alerts.

## Contributing

All code is licensed under the MIT license and we triage actively on GitHub. We enthusiastically welcome contributions and feedback. You can clone the repo and start contributing now. 

## Quick Start

1. Clone the repository to your machine
2. Build the library or framework
3. Add the ADAL library or framework your project


##Download

We've made it easy for you to have multiple options to use this library in your iOS project:

###Option 1: Git Submodule

If your project is managed in a git repository you can include ADAL as a git submodule:

    git submodule add https://github.com/AzureAD/azure-activedirectory-library-for-objc adal
    cd adal
    git checkout tags/2.1.0
    cd ..
    git add adal
    git commit -m "Use ADAL git submodule at 2.1.0"
    git push
    
We recommend only syncing to specific release tags to make sure you're at a known spot in the code.

###Option 2: Source Zip

To download a copy of the source code, click "Download ZIP" on the right side of the page or click [here](https://github.com/AzureAD/azure-activedirectory-library-for-objc/archive/1.2.5.tar.gz).

###Option 3: Cocoapods

    pod 'ADAL', '~> 2.1.0'

See [CocoaPods](https://cocoapods.org) for more information on setting up a PodFile

## Usage

### Caching

#### iOS

##### Keychain Setup

Click on your project in the Navigator pane in Xcode. Click on your application target and
then the "Capabilities" tab. Scroll down to "Keychain Sharing" and flip the switch on. Add
"com.microsoft.adalcache" to that list.

Alternatively you can disable keychain sharing by setting the keychain sharing group to nil.
your application's bundle id.

```Objective-C
    [[ADAuthenticationSettings sharedInstance] setSharedCacheKeychainGroup:nil];
```

##### Inspecting the Cache

If you need to inspect the cache in your app, you can do it through the ADKeychainTokenCache interface.

#### Mac OS X

Keychain is not directly supported by ADAL on Mac OS X. The default caching implementation will keep around tokens for the life time of the process, but they will not be persisted. If you wish to persist tokens you must implement the ADTokenCacheDelegate and provide it on AuthenticationContext creation

```Objective-C
@protocol ADTokenCacheDelegate <NSObject>

- (void)willAccessCache:(nonnull ADTokenCache *)cache;
- (void)didAccessCache:(nonnull ADTokenCache *)cache;
- (void)willWriteCache:(nonnull ADTokenCache *)cache;
- (void)didWriteCache:(nonnull ADTokenCache *)cache;

@end
```

In this delegate you can call -serialize and -deserialize on the cache object to save or update the cache in the form of an NSData binary blob.


### Quick Start

The starting point for the API is in ADAuthenticationContext.h header. ADAuthenticationContext is the main class used for obtaining, caching and supplying access tokens.

#### How to quickly get a token from the SDK:

```Objective-C

+ (void)getToken:(void (^)(NSString*))completionBlock;
{
    ADAuthenticationError *error = nil;
    authContext = [ADAuthenticationContext authenticationContextWithAuthority:@"https://login.microsoftonline.com/common"
                                                                        error:&error];
        
    [authContext acquireTokenWithResource:@"https://graph.windows.net"                 
                                 clientId:@"<Your Client ID>"                          // Comes from App Portal
                              redirectUri:[NSURL URLWithString:@"<Your Redirect URI>"] // Comes from App Portal
                          completionBlock:^(ADAuthenticationResult *result)
    {
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

    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:yourAppURL];
    NSString *authHeader = [NSString stringWithFormat:@"Bearer %@", accessToken];
    [request addValue:authHeader forHTTPHeaderField:@"Authorization"];
            
    NSOperationQueue *queue = [[NSOperationQueue alloc] init];
            
    [NSURLConnection sendAsynchronousRequest:request
                                       queue:queue
                           completionHandler:^(NSURLResponse *response, NSData *data, NSError *error)
    {
    	// Process Response Here
    }];
```

### Brokered Authentication

If your app requires conditional access or certificate authentication (currently in preview) support, you must set up your AuthenticationContext and redirectURI to be able to talk to the Azure Authenticator app.


#### Enable Broker Mode on Your Context
Broker is enabled on a per-authentication-context basis. You must set your credentials type if you wish ADAL to call to broker:

```Objective-C
/*! See the ADCredentialsType enumeration definition for details */
@property ADCredentialsType credentialsType;
```

The AD_CREDENTIALS_AUTO setting will allow ADAL to try to call out to the broker, AD_CREDENTIALS_EMBEDDED will prevent ADAL from calling to the broker.

#### Registering a URL Scheme
ADAL uses URLs to invoke the broker and then return back to your app. To finish that round trip you need a URL scheme registered for your app. We recommend making the URL scheme fairly unique to minimize the chances of another app using the same URL scheme.

```
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleTypeRole</key>
        <string>Editor</string>
        <key>CFBundleURLName</key>
        <string>com.MSOpenTech.MyTestiOSApp</string>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>x-msauth-mytestiosapp</string>
        </array>
    </dict>
</array>
```

#### LSApplicationQueriesSchemes
ADAL uses –canOpenURL: to check if the broker is installed on the device. in iOS 9 Apple locked down what schemes an application can query for. You will need to add “msauth” to the LSApplicationQueriesSchemes section of your info.plist file.

```
<key>LSApplicationQueriesSchemes</key>
<array>
     <string>msauth</string>
</array>
````

#### Redirect URI
This adds extra requirements on your redirect URI. Your redirect URI must be in the proper form.

```
<app-scheme>://<your.bundle.id>
ex: x-msauth-mytestiosapp://com.microsoft.mytestiosapp
```

This Redirect URI needs to be registered on the app portal as a valid redirect URI. Additionally a second "msauth" form needs to be registered to handle certificate authentication in Azure Authenticator.

```
msauth://code/<broker-redirect-uri-in-url-encoded-form>
ex: msauth://code/x-msauth-mytestiosapp%3A%2F%2Fcom.microsoft.mytestiosapp
```

### Caching

####


### Diagnostics


#### Logs

ADAL relies heavily on logging to diagnose issues. It is highly recommended that you set
an ADAL logging callback and provide a way for users to submit logs when they are having
authentication issues. 

##### Logging Callback

You can set a callback to capture ADAL logging and incorporate it in your own application's
logging:

```objective-c
/*!
    The LogCallback block for the ADAL logger
 
    @param  logLevel        The level of the log message
    @param  message         A short log message describing the event that occurred, this string will not contain PII.
    @param  additionalInfo  A longer message that may contain PII and other details relevant to the event.
    @param  errorCode       An integer error code if the log message is an error.
    @param  userInfo        A dictionary with other information relevant to the log message. The information varies,
                            for most error messages the error object will be in the "error" key.
 */
typedef void (^LogCallback)(ADAL_LOG_LEVEL logLevel,
                            NSString *message,
                            NSString *additionalInfo,
                            NSInteger errorCode,
                            NSDictionary *userInfo);
```


Otherwise ADAL outputs to NSLog by default, which will print messages on the console.

##### Example Log Message

The message portion of ADAL iOS are in the format of ADALiOS [timestamp - correlation_id] message

```
ADAL [2015-06-22 19:42:53 - 1030CB25-798F-4A6F-97DF-04A3A3E9DFF2] ADAL API call [Version - 2.1.0]
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
    [[ADAuthenticationSettings sharedInstance] setSharedCacheKeychainGroup:nil];
```

**ADAL keeps returning SSL errors in iOS 9 and later**

iOS 9 added App Transport Security (ATS). ATS restricts apps from accessing the internet unless they meet several security requirements including TLS 1.2 and SHA-256. It also prevents network traces that rely on self signed certs to crack SSL from working. Disabling ATS must be done in the Application's info.plist file, see [documentation on the NSAppTransport info.plist key](https://developer.apple.com/library/ios/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/uid/TP40009251-SW33) for more information.


## License

Copyright (c) Microsoft Corporation.  All rights reserved. Licensed under the MIT License (the "License");

## We Value and Adhere to the Microsoft Open Source Code of Conduct

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
