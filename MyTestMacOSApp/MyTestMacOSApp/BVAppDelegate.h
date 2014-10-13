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
    IBOutlet NSTextField *_resultLabel;
    NSPersistentStoreCoordinator *_persistentStoreCoordinator;
    NSManagedObjectModel         *_managedObjectModel;
    NSManagedObjectContext       *_managedObjectContext;
}

@property (assign) IBOutlet NSWindow *window;
@property (weak, nonatomic) IBOutlet NSTextField *resultLabel;

@property (readonly, strong, nonatomic) NSPersistentStoreCoordinator *persistentStoreCoordinator;
@property (readonly, strong, nonatomic) NSManagedObjectModel *managedObjectModel;
@property (readonly, strong, nonatomic) NSManagedObjectContext *managedObjectContext;

- (IBAction)saveAction:(id)sender;
- (IBAction)endToEndAction:(id)sender;
- (IBAction)showUsersAction:(id)sender;

@end
