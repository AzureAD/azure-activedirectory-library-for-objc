

#import <ADAL/ADAL.h>
#import "ADHomeViewController.h"
#import "AuthenticationService.h"

static NSString *s_authority = @"https://login.microsoftonline.com/common/oauth2/authorize";
static NSString *s_clientId = @"bc5beb43-ef30-4260-ab0a-d7603134248a";

static NSString *s_resultStringFormat = @"<!DOCTYPE html> \
<html><head><title>Authentication result</title></head><body><table style=\"font-size:10pt;\"> \
<tr><td>Error: </td><td><font color=\"red\">%@</font></td></tr> \
<tr><td>Status: </td><td>%@</td></tr> \
<tr><td>Identity Provider: </td><td>%@</td></tr> \
<tr><td>Given Name: </td><td>%@</td></tr> \
<tr><td>Family Name: </td><td>%@</td></tr> \
<tr><td>Unique Name: </td><td>%@</td></tr><tr> \
<td>upn: </td><td>%@</td></tr> \
<td>Access token: </td><td>%@</td></tr> \
</table></body></html>";

static NSString *s_resultStringEmpty = @"<!DOCTYPE html><html><head><title></title></head><body></body></html>";

@interface ADHomeViewController()

@property (weak, nonatomic) IBOutlet UIView *containerView;
@property (weak, nonatomic) IBOutlet UIWebView *resultWebView;
@property (weak, nonatomic) IBOutlet UITextField *resourceTextView;
@property (weak, nonatomic) IBOutlet UITextField *userIdTextView;
@property (weak, nonatomic) IBOutlet UIBarButtonItem *signInButton;
@property (weak, nonatomic) IBOutlet UIBarButtonItem *acquireTokenButton;
@property (weak, nonatomic) IBOutlet UIToolbar *toolbar;

@end

@implementation ADHomeViewController

#pragma mark view life cycles

- (void)viewDidLoad {
    [super viewDidLoad];
    
    [_containerView setBackgroundColor:[UIColor whiteColor]];
    [_resultWebView setBackgroundColor:[UIColor whiteColor]];
    
    [self addOrRemoveToolbarButton:NO];
    
    AuthenticationService *authService = [AuthenticationService sharedInstance];
    
    authService.authority = s_authority;
    authService.clientId = s_clientId;
    
    NSString *redirectUrl = [self readRedirectUrl];
    authService.redirectUri = [NSURL URLWithString:redirectUrl];
    
    [self updateAuthInfo];
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    [self setupKVO];
}

- (void)viewDidDisappear:(BOOL)animated {
    [super viewDidDisappear:animated];
    [self tearDownKVO];
}

#pragma mark KVO

- (void)setupKVO {
    AuthenticationService *authService = [AuthenticationService sharedInstance];
    
    [authService addObserver:self
                  forKeyPath:NSStringFromSelector(@selector(authenticationResult))
                     options:NSKeyValueObservingOptionNew | NSKeyValueObservingOptionOld context:nil];
    
    [authService addObserver:self
                  forKeyPath:NSStringFromSelector(@selector(userLoggedIn))
                     options:NSKeyValueObservingOptionNew | NSKeyValueObservingOptionOld context:nil];
}

- (void)tearDownKVO {
    AuthenticationService *authService = [AuthenticationService sharedInstance];
    [authService removeObserver:self forKeyPath:NSStringFromSelector(@selector(authenticationResult))];
    [authService removeObserver:self forKeyPath:NSStringFromSelector(@selector(userLoggedIn))];
}

- (void)observeValueForKeyPath:(NSString *)keyPath ofObject:(id)object change:(NSDictionary *)change context:(void *)context
{
    @synchronized (self) {
        if([keyPath isEqualToString:NSStringFromSelector(@selector(authenticationResult))]) {
            [self displayResult:(change[NSKeyValueChangeNewKey])];
            
        } else if ([keyPath isEqualToString:NSStringFromSelector(@selector(userLoggedIn))]) {
            [self updateButtonStatus:[change[NSKeyValueChangeNewKey] boolValue]];
        }
    }
}

#pragma mark button actions

- (IBAction)signinButtonAction:(id)sender {
    if ([[AuthenticationService sharedInstance] userLoggedIn]) {
        [[AuthenticationService sharedInstance] signoutUser];
    } else {
        [[AuthenticationService sharedInstance] acquireTokenForNewUser];
    }
}

- (IBAction)acquireTokenAction:(id)sender {
    [self updateAuthInfo];
    [[AuthenticationService sharedInstance] acquireTokenSilent];
}

#pragma mark private methods

- (void)updateAuthInfo
{
    AuthenticationService *authService = [AuthenticationService sharedInstance];
    
    authService.resource = [_resourceTextView text];
    authService.userId = [_userIdTextView text];
}

- (void)displayResult:(id)result {
    NSString *htmlResult = s_resultStringEmpty;
    
    if (result && result != [NSNull null]) {
        ADAuthenticationResult *authenticationResult = result;
        ADUserInformation *userInfo = authenticationResult.tokenCacheItem.userInformation;
        
        htmlResult = [NSString stringWithFormat:s_resultStringFormat,
                      authenticationResult.error ? authenticationResult.error.errorDetails : @"",
                      [self resultStatusToString:authenticationResult.status],
                      userInfo.identityProvider,
                      userInfo.givenName,
                      userInfo.familyName,
                      userInfo.uniqueName,
                      userInfo.upn,
                      authenticationResult.accessToken];
        
        if (authenticationResult.status != AD_SUCCEEDED || authenticationResult.error)
        {
            [[AuthenticationService sharedInstance] signoutUser];
        }
    }
    
    dispatch_async(dispatch_get_main_queue(), ^{
        [_resultWebView loadHTMLString:htmlResult baseURL:nil];
    });
}

- (void)updateButtonStatus:(BOOL)userLoggedIn {
    dispatch_async(dispatch_get_main_queue(), ^{
        [self.signInButton setTitle:(userLoggedIn ? @"Sign out" : @"Sign in")];
        [self addOrRemoveToolbarButton:userLoggedIn];
    });
}

- (void)addOrRemoveToolbarButton:(BOOL)userSignedIn {
    [_acquireTokenButton setEnabled:userSignedIn];
}

- (NSString *)resultStatusToString:(ADAuthenticationResultStatus)status {
    switch (status) {
    case AD_SUCCEEDED:
        return @"Succeeded";
        
    case AD_USER_CANCELLED:
        return @"Cancelled";
        
    case AD_FAILED:
        return @"Failed";
        
    default:
        return @"<unknown>";
    }
}

- (NSString *)readRedirectUrl {
    NSString *infoPlist = [[NSBundle mainBundle] pathForResource:@"Info" ofType:@"plist"];
    
    NSDictionary *infoDictionary = [NSDictionary dictionaryWithContentsOfFile:infoPlist];
    
    NSArray *urlTypes = [infoDictionary objectForKey:@"CFBundleURLTypes"];
    
    if (!urlTypes || [urlTypes count] == 0) {
        @throw @"Please set url types in the info.plist file.";
    }
    
    NSDictionary *urlType = [urlTypes objectAtIndex:0];
    NSString *urlName = [urlType objectForKey:@"CFBundleURLName"];
    
    if (!urlName) {
        @throw @"Url name is required to be set in info.plist.";
    }
    
    NSArray *urlSchemes = [urlType objectForKey:@"CFBundleURLSchemes"];
    
    if (!urlSchemes || [urlSchemes count] == 0) {
        @throw @"Please set url schemes in the info.plist file.";
    }
    
    NSString *urlScheme = [urlSchemes objectAtIndex:0];
    
    if (!urlScheme) {
        @throw @"Url scheme is required to be set in info.plist.";
    }
    
    // @"x-msauth-adal-sample-app-ios://com.microsoft.adal.iOSSampleApp"
    return [NSString stringWithFormat:@"%@://%@", urlScheme, urlName];
}

@end
