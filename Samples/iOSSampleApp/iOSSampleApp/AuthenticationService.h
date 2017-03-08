
#import <Foundation/Foundation.h>

@interface AuthenticationService : NSObject

@property (nonatomic, strong) NSString *authority;
@property (nonatomic, strong) NSString *resource;
@property (nonatomic, strong) NSString *clientId;
@property (nonatomic, strong) NSURL *redirectUri;
@property (nonatomic, strong) NSString *userId;
@property (nonatomic, strong) NSString *uniqueId;

@property (nonatomic, strong) ADAuthenticationResult *authenticationResult;
@property (assign) BOOL userLoggedIn;

+ (AuthenticationService *)sharedInstance;

+ (instancetype)new __attribute__((unavailable("new is unavailable, use sharedInstance instead.")));
- (instancetype)init __attribute__((unavailable("init is unavailable, use sharedInstance instead.")));

- (void)useToken:(NSString *)accessToken;
- (void)handleWrongUser;
- (void)acquireTokenForNewUser;
- (void)acquireTokenOnInvalidGrant;
- (void)acquireTokenInteractionRequired;
- (void)acquireTokenSilent;
- (void)signoutUser;

@end
