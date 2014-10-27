//
//  BVAppDelegate.h
//  MyTestMacOSApp
//
//  Created by Boris Vidolov on 3/6/14.
//  Copyright (c) 2014 Microsoft Open Technologies, Inc. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface BVAppDelegate : NSObject <NSApplicationDelegate>
{
//@private:
    IBOutlet NSWindow *_window;
    IBOutlet NSTextView *_resultField;
    IBOutlet NSTextView *_samlAssertionField;
    NSPersistentStoreCoordinator *_persistentStoreCoordinator;
    NSManagedObjectModel         *_managedObjectModel;
    NSManagedObjectContext       *_managedObjectContext;
}

@property (assign) IBOutlet NSWindow *window;
@property (assign) IBOutlet NSTextView *resultField;
@property (assign) IBOutlet NSTextView *samlAssertionField;

@property (readonly, strong, nonatomic) NSPersistentStoreCoordinator *persistentStoreCoordinator;
@property (readonly, strong, nonatomic) NSManagedObjectModel *managedObjectModel;
@property (readonly, strong, nonatomic) NSManagedObjectContext *managedObjectContext;

- (IBAction)saveAction:(id)sender;
- (IBAction)endToEndAction:(id)sender;
- (IBAction)showUsersAction:(id)sender;
- (IBAction)expireAllAction:(id)sender;
- (IBAction)clearCacheAndCookiesAction:(id)sender;
- (IBAction)refreshTokenFlowAction:(id)sender;
- (IBAction)acquireTokenSilentAction:(id)sender;
- (IBAction)promptAlwaysAction:(id)sender;
- (IBAction)samlAssertionAction:(id)sender;

@end
