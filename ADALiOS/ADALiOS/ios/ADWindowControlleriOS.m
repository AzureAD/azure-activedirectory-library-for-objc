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

#import "ADWindowController.h"

#import "ADNTLMHandler.h"
#import "UIApplication+ADExtensions.h"
#import "ADCustomHeaderHandler.h"
#import "ADAuthenticationViewController.h"
#import "ADAuthenticationBroker.h"

static NSString *const AD_IPAD_STORYBOARD = @"ADAL_iPad_Storyboard";
static NSString *const AD_IPHONE_STORYBOARD = @"ADAL_iPhone_Storyboard";

NSString *const AD_FAILED_NO_CONTROLLER = @"The Application does not have a current ViewController";
NSString *const AD_FAILED_NO_RESOURCES  = @"The required resource bundle could not be loaded. Please read the ADALiOS readme on how to build your application with ADAL provided authentication UI resources.";

@implementation ADWindowController
{
    BOOL                                _fullScreen;
    
    UIViewController*                   _parent;
    __weak UINavigationController*      _navigationController;
    ADAuthenticationViewController*     _authenticationViewController;
}

+ (NSString*)getStoryboardName
{
    return (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad)
    ? AD_IPAD_STORYBOARD
    : AD_IPHONE_STORYBOARD;
}

// Retrieve the current storyboard from the resources for the library. Attempts to use ADALiOS bundle first
// and if the bundle is not present, assumes that the resources are build with the application itself.
// Raises an error if both the library resources bundle and the application fail to locate resources.
+ (UIStoryboard *)storyboard
{
    NSBundle* bundle = [ADAuthenticationBroker frameworkBundle];//May be nil.
    if (!bundle)
    {
        //The user did not use ADALiOS.bundle. The resources may be manually linked
        //to the app by referencing the storyboards directly.
        bundle = [NSBundle mainBundle];
    }
    NSString* storyboardName = [self getStoryboardName];
    if ([bundle pathForResource:storyboardName ofType:@"storyboardc"])
    {
        //Despite Apple's documentation, storyboard with name actually throws, crashing
        //the app if the story board is not present, hence the if above.
        UIStoryboard* storyBoard = [UIStoryboard storyboardWithName:storyboardName bundle:bundle];
        if (storyBoard)
            return storyBoard;
    }
    
    return nil;
}

- (BOOL)unpackStoryboard
{
    // Load our resource bundle, find the navigation controller for the authentication view, and then the authentication view
    UINavigationController* navigationController = [[ADWindowController storyboard] instantiateViewControllerWithIdentifier:@"LogonNavigator"];
    
    if (!navigationController)
        return NO;
    
    _navigationController = navigationController;
    _authenticationViewController = (ADAuthenticationViewController *)[navigationController.viewControllers objectAtIndex:0];
    
    return YES;
}

- (ADAuthenticationError*)showWindowWithStartURL:(NSURL*)startURL
                                          endURL:(NSURL*)endURL
{
    if (!_parent)
    {
        // Must have a parent view controller to start the authentication view
        _parent = [UIApplication adCurrentViewController];
    }
    
    if (!_parent)
    {
        return [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_NO_MAIN_VIEW_CONTROLLER
                                                      protocolCode:nil
                                                      errorDetails:AD_FAILED_NO_CONTROLLER];
    }
    
    if (!_navigationController && !([self unpackStoryboard]))
    {
        return [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_MISSING_RESOURCES
                                                      protocolCode:nil
                                                      errorDetails:AD_FAILED_NO_RESOURCES];
        
    }
    
    if ( _fullScreen == YES )
        [_navigationController setModalPresentationStyle:UIModalPresentationFullScreen];
    else
        [_navigationController setModalPresentationStyle:UIModalPresentationFormSheet];
    
    // Show the authentication view
    dispatch_async( dispatch_get_main_queue(), ^{
        [_parent presentViewController:_navigationController animated:YES completion:^{
        // Instead of loading the URL immediately on completion, get the UI on the screen
        // and then dispatch the call to load the authorization URL
            
            [_authenticationViewController startWithURL:startURL
                                               endAtURL:endURL];
        }];
    });
    
    return nil;
}

- (void)dismissAnimated:(BOOL)animated
             completion:(void(^)())completion
{
    [_parent dismissViewControllerAnimated:animated completion:completion];
}

- (void)setParentController:(UIViewController *)parentController
{
    _parent = parentController;
}

- (void)setFullScreen:(BOOL)fullScreen
{
    _fullScreen = fullScreen;
}

@end
