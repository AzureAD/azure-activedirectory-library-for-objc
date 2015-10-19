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


#import "ADTestAppLogViewController.h"
#import <ADALiOS/ADAL.h>
#import "ADTestAppLogger.h"

static NSString* _StringForLevel(ADAL_LOG_LEVEL level)
{
    switch (level)
    {
        case ADAL_LOG_LEVEL_ERROR : return @"ERR";
        case ADAL_LOG_LEVEL_INFO : return @"INF";
        case ADAL_LOG_LEVEL_VERBOSE : return @"VER";
        case ADAL_LOG_LEVEL_WARN : return @"WAR";
        default:
            return @"???";
    }
}

NSDictionary* s_errorStringAttributes = nil;
NSDictionary* s_statusStringAttributes = nil;
NSDictionary* s_defaultStringAttributes = nil;

NSAttributedString* s_newLine = nil;

@interface ADTestAppLogViewController ()
{
    NSTextStorage* _textStorage;
}

@property IBOutlet UITextView* logView;

@end

@implementation ADTestAppLogViewController

+ (void)initialize
{
    // Grab the default body font
    UIFontDescriptor* defaultFontDescriptor = [UIFontDescriptor preferredFontDescriptorWithTextStyle:UIFontTextStyleBody];
    UIFont* defaultFont = [UIFont fontWithDescriptor:defaultFontDescriptor size:0.0];
    
    s_defaultStringAttributes = @{ NSFontAttributeName : defaultFont };
    
    uint32_t existingTraitsWithNewTrait = UIFontDescriptorTraitBold;
    UIFontDescriptor* boldFontDescriptor = [defaultFontDescriptor fontDescriptorWithSymbolicTraits:existingTraitsWithNewTrait];
    UIFont* boldFont = [UIFont fontWithDescriptor:boldFontDescriptor size:0.0];
    
    s_errorStringAttributes = @{ NSForegroundColorAttributeName : [UIColor redColor],
                                 NSFontAttributeName : boldFont };
    
    s_statusStringAttributes = @{ NSFontAttributeName: boldFont,
                                  NSUnderlineStyleAttributeName : [NSNumber numberWithInt:NSUnderlineStyleSingle] };
    
    s_newLine = [[NSAttributedString alloc] initWithString:@"\n"];
}

- (id)initWithCoder:(NSCoder *)aDecoder
{
    if (!(self = [super initWithCoder:aDecoder]))
    {
        return nil;
    }
    
    return self;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    
    _textStorage = [_logView textStorage];
    
    [ADLogger setLogCallBack:^(ADAL_LOG_LEVEL logLevel, NSString *message, NSString *additionalInformation, NSInteger errorCode)
     {
         NSAttributedString* logLine = nil;
         if (errorCode == AD_ERROR_SUCCEEDED)
         {
             NSString* logMessage = [NSString stringWithFormat:@"%@ %@ - %@", _StringForLevel(logLevel), message, additionalInformation];
             logLine = [[NSAttributedString alloc] initWithString:logMessage
                                                       attributes:s_defaultStringAttributes];
         }
         else
         {
             NSString* logMessage = [NSString stringWithFormat:@"%@ (error: %ld) %@ - %@", _StringForLevel(logLevel), (long)errorCode, message, additionalInformation];
             logLine = [[NSAttributedString alloc] initWithString:logMessage
                                                       attributes:s_errorStringAttributes];
         }
         NSLog(@"%@", logLine);
         dispatch_async(dispatch_get_main_queue(), ^{
             [_textStorage appendAttributedString:logLine];
             [_textStorage appendAttributedString:s_newLine];
         });
     }];
    
    [ADTestAppLogger registerLogCallback:^(NSString *message, TALogType type) {
        NSDictionary* attributes = nil;
        
        switch (type)
        {
            case TALogStatus: attributes = s_statusStringAttributes; [_textStorage appendAttributedString:s_newLine]; break;
            case TALogError : attributes = s_errorStringAttributes; break;
            default: break;
        }
        
        NSAttributedString* logLine = [[NSAttributedString alloc] initWithString:message attributes:attributes];
        dispatch_async(dispatch_get_main_queue(), ^{
            [_textStorage appendAttributedString:logLine];
            [_textStorage appendAttributedString:s_newLine];
        });
    }];
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

/*
#pragma mark - Navigation

// In a storyboard-based application, you will often want to do a little preparation before navigation
- (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender
{
    // Get the new view controller using [segue destinationViewController].
    // Pass the selected object to the new view controller.
}
*/

@end
