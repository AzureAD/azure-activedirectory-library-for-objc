Active Directory Authentication Library (ADAL)
=====================================

The library wraps OAuth2 protocols implementation, needed for a native iOS app to authenticate with the Azure Active Directory. 

Integrate library to your application:
1 Clone the repository to your machine
2 Build the library
3 Add the ADALiOS library to your project
4 Add ADALiOSFramework to “Target Dependences” build phase of your application
5 Add ADALiOSBundle.bundle to “Copy Bundle Resources” build phase of your application
6 Add libADALiOS to “Link With Libraries” phase.

Where to start:
1.	Check the ADAuthenticationContext.h header. ADAuthenticationContext is the main class, used for obtaining, caching and supplying access tokens.</br>
2.	See the http://www.cloudidentity.com blog to get familiar with the ADAL library.</br>


