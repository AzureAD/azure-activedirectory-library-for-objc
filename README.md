#Microsoft Azure Active Directory Authentication Library (ADAL) for iOS and OSX
=====================================

[![Build Status](https://travis-ci.org/MSOpenTech/azure-activedirectory-library-for-ios.png)](https://travis-ci.org/MSOpenTech/azure-activedirectory-library-for-ios)


ADALiOS-convergence was an experimental version of ADAL for developers to try out our v2 endpoint and won't receive new features. We recommend using other third party OAuth2 libraries for production apps targeting the AAD v2 and b2c endpoints. 

## Samples and Documentation

There is a native iOS sample available [here](https://github.com/Azure-Samples/active-directory-ios-native-nxoauth2-b2c).

## Community Help and Support

We leverage [Stack Overflow](http://stackoverflow.com/) to work with the community on supporting Azure Active Directory and its SDKs, including this one! We highly recommend you ask your questions on Stack Overflow (we're all on there!) Also browser existing issues to see if someone has had your question before. 

We recommend you use the "adal" tag so we can see it! Here is the latest Q&A on Stack Overflow for ADAL: [http://stackoverflow.com/questions/tagged/adal](http://stackoverflow.com/questions/tagged/adal)

## Quick Start

1. Clone the repository to your machine
2. Build the library
3. Add the ADALiOS library to your project
4. Add the storyboards from the ADALiOSBundle to your project resources
5. Add libADALiOS to “Link With Libraries” phase. 

##Common problems

**Application, using the ADAL library crashes with the following exception:**<br/> *** Terminating app due to uncaught exception 'NSInvalidArgumentException', reason: '+[NSString isStringNilOrBlank:]: unrecognized selector sent to class 0x13dc800'<br/>
**Solution:** Make sure that you add the -ObjC flag to "Other Linker Flags" build setting of the application. For more information, see Apple documentation for using static libraries:<br/> https://developer.apple.com/library/ios/technotes/iOSStaticLibraries/Articles/configuration.html#//apple_ref/doc/uid/TP40012554-CH3-SW1.

## License

Copyright (c) Microsoft Corporation.  All rights reserved. Licensed under the MIT License (the "License"); 
