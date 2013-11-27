azure-activedirectory-library-for-ios
=====================================

Active Directory Authentication Library (ADAL)</br>
The library wraps OAuth2 protocols implementation, needed for a native iOS app to authenticate with the Azure Active Directory. </br>

Integrate library to your application:
#	Clone the repository to your machine
#	Build the library
#	Add the ADALiOS library to your project
#	Add ADALiOSFramework to “Target Dependences” build phase of your application
#	Add ADALiOSBundle.bundle to “Copy Bundle Resources” build phase of your application
#	Add libADALiOS to “Link With Libraries” phase.

Where to start:
1.	Check the ADAuthenticationContext.h header. ADAuthenticationContext is the main class, used for obtaining, caching and supplying access tokens.
2.	See the http://www.cloudidentity.com blog to get familiar with the ADAL library.


