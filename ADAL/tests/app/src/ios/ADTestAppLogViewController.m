// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import "ADTestAppLogViewController.h"
#import "ADALTelemetry.h"
#import "ADALLogger.h"

@interface ADTestAppLogViewController () <ADDispatcher>

@end

@implementation ADTestAppLogViewController
{
    UITextView* _logView;
    NSTextStorage* _logStorage;
}

static NSAttributedString* s_attrNewLine = nil;

+ (void)initialize
{
    s_attrNewLine = [[NSAttributedString alloc] initWithString:@"\n"];
}

- (id)init
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    UITabBarItem* tabBarItem = [[UITabBarItem alloc] initWithTitle:@"Log" image:nil tag:0];
    [self setTabBarItem:tabBarItem];
    
    _logStorage = [NSTextStorage new];
    
    [self setEdgesForExtendedLayout:UIRectEdgeNone];
    
    [ADALLogger setLoggerCallback:^(ADAL_LOG_LEVEL logLevel, NSString *message, BOOL containsPii)
     {
        [self appendNewLogLine:message];
    }];
    
    [ADALLogger setLevel:ADAL_LOG_LEVEL_VERBOSE];
    
    [[ADALTelemetry sharedInstance] addDispatcher:self aggregationRequired:YES];
    
    return self;
}

- (void)appendNewLogLine:(NSString *)log
{
    NSLog(@"%@", log);
    
    NSAttributedString* attrLog = [[NSAttributedString alloc] initWithString:log];
    
    dispatch_async(dispatch_get_main_queue(), ^{
        if (_logView)
        {
            [[_logView textStorage] appendAttributedString:attrLog];
            [[_logView textStorage] appendAttributedString:s_attrNewLine];
            
            [self scrollToBottom];
        }
        else
        {
            
            [_logStorage appendAttributedString:attrLog];
            [_logStorage appendAttributedString:s_attrNewLine];
        }
    });
}

- (void)dispatchEvent:(nonnull NSDictionary<NSString*, NSString*> *)event
{
    NSString *log = [NSString stringWithFormat:@"ADALTelemetry event dispatched: %@", event];
    [self appendNewLogLine:log];
}

- (void)scrollToBottom
{
    NSRange range = NSMakeRange(_logView.text.length, 0);
    [_logView scrollRangeToVisible:range];
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    
    _logView = [[UITextView alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    [_logView setAutoresizingMask:UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight];
    [[_logView textStorage] appendAttributedString:_logStorage];
    [_logView setScrollsToTop:NO];
    
    // Move the content down so it's not covered by the status bar
    [_logView setContentInset:UIEdgeInsetsMake(20, 0, 0, 0)];
    [_logView setContentOffset:CGPointMake(0, -20)];
    
    _logStorage = nil;
    [self scrollToBottom];
    [self.view addSubview:_logView];
    //[self.view setBackgroundColor:[UIColor redColor]];
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
