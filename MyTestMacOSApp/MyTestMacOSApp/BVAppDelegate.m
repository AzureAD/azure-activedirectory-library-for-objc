//
//  BVAppDelegate.m
//  MyTestMacOSApp
//
//  Created by Boris Vidolov on 3/6/14.
//  Copyright (c) 2014 Microsoft Open Technologies, Inc. All rights reserved.
//

#import "BVAppDelegate.h"
#import <ADAL-OSX/ADAuthenticationContext.h>
#import <ADAL-OSX/ADLogger.h>
#import "BVSettings.h"
#import "BVTestInstance.h"
#import <ADAL-OSX/ADAuthenticationSettings.h>

@implementation BVAppDelegate

@synthesize window = _window;
@synthesize resultField = _resultField;
@synthesize samlAssertionField = _samlAssertionField;

@synthesize persistentStoreCoordinator = _persistentStoreCoordinator;
@synthesize managedObjectModel         = _managedObjectModel;
@synthesize managedObjectContext       = _managedObjectContext;

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    [_resultField setString:@"Response goes here"];
}


- (void) setStatus:(NSString*) message
{
    [_resultField setString:message];
}

- (void) appendStatus:(NSString*) message {
    
    NSMutableString* mutableString = [NSMutableString stringWithString:[[_resultField textStorage] string]];
    [mutableString appendString:message];
    [self setStatus:mutableString];
}

- (IBAction)samlAssertionAction:(id)sender
{
    BVSettings     *testData    = [BVSettings new];
    BVTestInstance *aadInstance = [[testData.testAuthorities objectForKey:sAADTestInstance] retain];
    
    NSString* authority = aadInstance.authority;//params.authority;
    NSString* clientId = aadInstance.clientId;
    NSString* resourceString = aadInstance.resource;
    ADAuthenticationError * error;
    ADAuthenticationContext* context = [ADAuthenticationContext authenticationContextWithAuthority:authority validateAuthority:aadInstance.validateAuthority error:&error];
    if (!context)
    {
        [self setStatus:error.errorDetails];
        return;
    }
    
    [context acquireTokenForAssertion:[[_samlAssertionField textStorage] string] assertionType:AD_SAML1_1 resource:resourceString clientId:clientId userId:aadInstance.userId completionBlock:^(ADAuthenticationResult *result) {
        if (result.status != AD_SUCCEEDED)
        {
            [self setStatus:result.error.errorDetails];
            return;
        }
        
        [self setStatus:result.tokenCacheStoreItem.accessToken];
    }];
}

- (IBAction)endToEndAction:(id)sender{
    // Do any additional setup after loading the view, typically from a nib.
    //Log everything
    [ADLogger setLevel:ADAL_LOG_LEVEL_VERBOSE];
    
    [self setStatus:@"Running End-to-End"];
    BVSettings     *testData    = [BVSettings new];
    BVTestInstance *aadInstance = [[testData.testAuthorities objectForKey:sAADTestInstance] retain];
    
    ADAuthenticationError   *error = nil;
    __block ADAuthenticationContext *context = [[ADAuthenticationContext authenticationContextWithAuthority:aadInstance.authority
                                                                                          validateAuthority: NO
                                                                                                      error:&error] retain];
    
    [context acquireTokenWithResource:aadInstance.resource
                             clientId:aadInstance.clientId
                          redirectUri:[NSURL URLWithString:aadInstance.redirectUri]
                       promptBehavior:AD_PROMPT_AUTO
                               userId:aadInstance.userId
                 extraQueryParameters: aadInstance.extraQueryParameters
                      completionBlock:^(ADAuthenticationResult *result)
     {
         if (AD_SUCCEEDED == result.status)
         {
             [self setStatus: [NSString stringWithFormat:@"AcquireToken succeeded with access token: %@", result.accessToken]];
         }
         else
         {
             [self setStatus: [NSString stringWithFormat:@"AcquireToken failed with access token: %@", result.error.errorDetails]];
         }
         
         [context release];
     }];
    
    [aadInstance release];
    [testData release];
}


- (IBAction)showUsersAction:(id)sender{
    
    [self setStatus:@"Getting users from cache...\n"];
    ADAuthenticationError* error = nil;
    id<ADTokenCacheStoring> cache = [ADAuthenticationSettings sharedInstance].defaultTokenCacheStore;
    NSArray* array = [cache allItemsWithError:&error];
    if (error)
    {
        [self appendStatus:error.errorDetails];
        return;
    }
    NSMutableSet* users = [NSMutableSet new];
    NSMutableString* usersStr = [NSMutableString new];
    for(ADTokenCacheStoreItem* item in array)
    {
        ADUserInformation *user = item.userInformation;
        if (!item.userInformation)
        {
            user = [ADUserInformation userInformationWithUserId:@"Unknown user" error:nil];
        }
        if (![users containsObject:user.userId])
        {
            //New user, add and print:
            [users addObject:user.userId];
            [usersStr appendFormat:@"%@: %@ %@\n", user.userId, user.givenName, user.familyName];
        }
    }
    [self appendStatus:usersStr];
    [usersStr release];
}


- (IBAction)expireAllAction:(id)sender{
    ADAuthenticationError* error = nil;
    [self setStatus:@"Attempt to expire...\n"];
    id<ADTokenCacheStoring> cache = [ADAuthenticationSettings sharedInstance].defaultTokenCacheStore;
    NSArray* array = [cache allItemsWithError:&error];
    if (error)
    {
        [self appendStatus:error.errorDetails];
        return;
    }
    
    
    [self appendStatus:[NSString stringWithFormat:@"Items found - %lu\n", (unsigned long)array.count]];
    for(ADTokenCacheStoreItem* item in array)
    {
        item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:0];
        [cache addOrUpdateItem:item error:&error];
    }
    if (error)
    {
        [self appendStatus:error.errorDetails];
    }
    else
    {
        [self appendStatus:@"Done."];
    }
}


- (IBAction)clearCacheAndCookiesAction:(id)sender{
    ADAuthenticationError* error = nil;
    [self setStatus:@"Clearing cache...\n"];
    id<ADTokenCacheStoring> cache = [ADAuthenticationSettings sharedInstance].defaultTokenCacheStore;
    NSArray* allItems = [cache allItemsWithError:&error];
    if (error)
    {
        [self appendStatus:error.errorDetails];
        return;
    }
    
    [self appendStatus:[NSString stringWithFormat: @"Total Items - %lu\n", (unsigned long)allItems.count]];
    NSString* status = @"Nothing in the cache.\n";
    if (allItems.count > 0)
    {
        [cache removeAllWithError:&error];
        if (error)
        {
            status = error.errorDetails;
        }
        else
        {
            status = @"Items removed.\n";
        }
    }
    [self appendStatus:status];
    
    [self appendStatus:@"\nRemoving cookies..."];
    NSHTTPCookieStorage* cookieStorage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    NSArray* cookies = cookieStorage.cookies;
    
    [self appendStatus:[NSString stringWithFormat: @"Total Cookies - %lu\n", (unsigned long)cookies.count]];
    if (cookies.count)
    {
        for(NSHTTPCookie* cookie in cookies)
        {
            [cookieStorage deleteCookie:cookie];
        }
        [self appendStatus:@"Cookies cleared.\n"];
    }
}


- (IBAction)refreshTokenFlowAction:(id)sender{
    
    BVSettings     *testData    = [BVSettings new];
    BVTestInstance *aadInstance = [[testData.testAuthorities objectForKey:sAADTestInstance] retain];
    
    NSString* authority = aadInstance.authority;
    NSString* clientId = aadInstance.clientId;
    NSString* resourceString =aadInstance.resource;
    
    [self setStatus:@"Attempt to refresh...\n"];
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [ADAuthenticationContext authenticationContextWithAuthority:authority validateAuthority:NO error:&error];
    if (!context)
    {
        [self appendStatus:error.errorDetails];
        return;
    }
    //We will leverage a multi-resource refresh token:
    ADTokenCacheStoreKey* key = [ADTokenCacheStoreKey keyWithAuthority:authority resource:resourceString clientId:clientId error:&error];
    if (!key)
    {
        [self appendStatus:error.errorDetails];
        return;
    }
    id<ADTokenCacheStoring> cache = context.tokenCacheStore;
    ADTokenCacheStoreItem* item = [cache getItemWithKey:key userId:nil error:nil];
    if (!item)
    {
        [self appendStatus:@"Missing cache item."];
        return;
    }
    
    [context acquireTokenByRefreshToken:item.refreshToken
                               clientId:clientId
                               resource:resourceString
                        completionBlock:^(ADAuthenticationResult *result)
     {
         if (result.error)
         {
             [self appendStatus:result.error.errorDetails];
         }
         else
         {
             [self appendStatus:result.tokenCacheStoreItem.accessToken];
         }
     }];
    
    [aadInstance release];
    [testData release];
    
}



- (IBAction)acquireTokenSilentAction:(id)sender{
    
}


- (IBAction)promptAlwaysAction:(id)sender{
    
    BVSettings     *testData    = [BVSettings new];
    BVTestInstance *aadInstance = [[testData.testAuthorities objectForKey:sAADTestInstance] retain];
    
    [self setStatus:@"Setting prompt always..."];
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* context = [ADAuthenticationContext authenticationContextWithAuthority:aadInstance.authority error:&error];
    if (!context)
    {
        [self appendStatus:error.errorDetails];
        return;
    }
    
    [context acquireTokenWithResource:aadInstance.resource
                             clientId:aadInstance.clientId
                          redirectUri:[NSURL URLWithString:aadInstance.redirectUri]
                       promptBehavior:AD_PROMPT_ALWAYS
                               userId:aadInstance.userId
                 extraQueryParameters: aadInstance.extraQueryParameters
                      completionBlock:^(ADAuthenticationResult *result)
     {
         if (result.status != AD_SUCCEEDED)
         {
             [self appendStatus:result.error.errorDetails];
             return;
         }
         
         [self appendStatus:result.tokenCacheStoreItem.accessToken];
     }];
    
    [aadInstance release];
    [testData release];
    
}

// Returns the directory the application uses to store the Core Data store file. This code uses a directory named "MSOpenTech.MyTestMacOSApp" in the user's Application Support directory.
- (NSURL *)applicationFilesDirectory
{
    NSFileManager *fileManager   = [NSFileManager defaultManager];
    NSURL         *appSupportURL = [[fileManager URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask] lastObject];
    
    return [appSupportURL URLByAppendingPathComponent:@"MSOpenTech.MyTestMacOSApp"];
}

// Creates if necessary and returns the managed object model for the application.
- (NSManagedObjectModel *)managedObjectModel
{
    if (_managedObjectModel) {
        return _managedObjectModel;
    }
    
    NSURL *modelURL = [[NSBundle mainBundle] URLForResource:@"MyTestMacOSApp" withExtension:@"momd"];
    _managedObjectModel = [[NSManagedObjectModel alloc] initWithContentsOfURL:modelURL];
    return _managedObjectModel;
}

// Returns the persistent store coordinator for the application. This implementation creates and return a coordinator, having added the store for the application to it. (The directory for the store is created, if necessary.)
- (NSPersistentStoreCoordinator *)persistentStoreCoordinator
{
    if (_persistentStoreCoordinator) {
        return _persistentStoreCoordinator;
    }
    
    NSManagedObjectModel *mom = [self managedObjectModel];
    if (!mom) {
        NSLog(@"%@:%@ No model to generate a store from", [self class], NSStringFromSelector(_cmd));
        return nil;
    }
    
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSURL *applicationFilesDirectory = [self applicationFilesDirectory];
    NSError *error = nil;
    
    NSDictionary *properties = [applicationFilesDirectory resourceValuesForKeys:@[NSURLIsDirectoryKey] error:&error];
    
    if (!properties) {
        BOOL ok = NO;
        if ([error code] == NSFileReadNoSuchFileError) {
            ok = [fileManager createDirectoryAtPath:[applicationFilesDirectory path] withIntermediateDirectories:YES attributes:nil error:&error];
        }
        if (!ok) {
            [[NSApplication sharedApplication] presentError:error];
            return nil;
        }
    } else {
        if (![[properties objectForKey:NSURLIsDirectoryKey] boolValue]) {
            // Customize and localize this error.
            NSString *failureDescription = [NSString stringWithFormat:@"Expected a folder to store application data, found a file (%@).", [applicationFilesDirectory path]];
            
            NSMutableDictionary *dict = [NSMutableDictionary dictionary];
            [dict setValue:failureDescription forKey:NSLocalizedDescriptionKey];
            error = [NSError errorWithDomain:@"YOUR_ERROR_DOMAIN" code:101 userInfo:dict];
            
            [[NSApplication sharedApplication] presentError:error];
            return nil;
        }
    }
    
    NSURL *url = [applicationFilesDirectory URLByAppendingPathComponent:@"MyTestMacOSApp.storedata"];
    NSPersistentStoreCoordinator *coordinator = [[NSPersistentStoreCoordinator alloc] initWithManagedObjectModel:mom];
    if (![coordinator addPersistentStoreWithType:NSXMLStoreType configuration:nil URL:url options:nil error:&error]) {
        [[NSApplication sharedApplication] presentError:error];
        return nil;
    }
    _persistentStoreCoordinator = coordinator;
    
    return _persistentStoreCoordinator;
}

// Returns the managed object context for the application (which is already bound to the persistent store coordinator for the application.)
- (NSManagedObjectContext *)managedObjectContext
{
    if (_managedObjectContext) {
        return _managedObjectContext;
    }
    
    NSPersistentStoreCoordinator *coordinator = [self persistentStoreCoordinator];
    if (!coordinator) {
        NSMutableDictionary *dict = [NSMutableDictionary dictionary];
        [dict setValue:@"Failed to initialize the store" forKey:NSLocalizedDescriptionKey];
        [dict setValue:@"There was an error building up the data file." forKey:NSLocalizedFailureReasonErrorKey];
        NSError *error = [NSError errorWithDomain:@"YOUR_ERROR_DOMAIN" code:9999 userInfo:dict];
        [[NSApplication sharedApplication] presentError:error];
        return nil;
    }
    _managedObjectContext = [[NSManagedObjectContext alloc] init];
    [_managedObjectContext setPersistentStoreCoordinator:coordinator];
    
    return _managedObjectContext;
}

// Returns the NSUndoManager for the application. In this case, the manager returned is that of the managed object context for the application.
- (NSUndoManager *)windowWillReturnUndoManager:(NSWindow *)window
{
    return [[self managedObjectContext] undoManager];
}

// Performs the save action for the application, which is to send the save: message to the application's managed object context. Any encountered errors are presented to the user.
- (IBAction)saveAction:(id)sender
{
    NSError *error = nil;
    
    if (![[self managedObjectContext] commitEditing]) {
        NSLog(@"%@:%@ unable to commit editing before saving", [self class], NSStringFromSelector(_cmd));
    }
    
    if (![[self managedObjectContext] save:&error]) {
        [[NSApplication sharedApplication] presentError:error];
    }
}

- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication *)sender
{
    // Save changes in the application's managed object context before the application terminates.
    
    if (!_managedObjectContext) {
        return NSTerminateNow;
    }
    
    if (![[self managedObjectContext] commitEditing]) {
        NSLog(@"%@:%@ unable to commit editing to terminate", [self class], NSStringFromSelector(_cmd));
        return NSTerminateCancel;
    }
    
    if (![[self managedObjectContext] hasChanges]) {
        return NSTerminateNow;
    }
    
    NSError *error = nil;
    if (![[self managedObjectContext] save:&error]) {
        
        // Customize this code block to include application-specific recovery steps.
        BOOL result = [sender presentError:error];
        if (result) {
            return NSTerminateCancel;
        }
        
        NSString *question = NSLocalizedString(@"Could not save changes while quitting. Quit anyway?", @"Quit without saves error question message");
        NSString *info = NSLocalizedString(@"Quitting now will lose any changes you have made since the last successful save", @"Quit without saves error question info");
        NSString *quitButton = NSLocalizedString(@"Quit anyway", @"Quit anyway button title");
        NSString *cancelButton = NSLocalizedString(@"Cancel", @"Cancel button title");
        NSAlert *alert = [[NSAlert alloc] init];
        [alert setMessageText:question];
        [alert setInformativeText:info];
        [alert addButtonWithTitle:quitButton];
        [alert addButtonWithTitle:cancelButton];
        
        NSInteger answer = [alert runModal];
        
        if (answer == NSAlertAlternateReturn) {
            return NSTerminateCancel;
        }
    }
    
    return NSTerminateNow;
}

@end
