//
//  SHOmniAuthTwitter.m
//  SHAccountManagerExample
//
//  Created by Seivan Heidari on 3/24/13.
//  Copyright (c) 2013 Seivan Heidari. All rights reserved.
//

#import "SHOmniAuthTwitter.h"
#import "SHOmniAuth.h"

#import "TWAPIManager.h"

#import "OAuthCore.h"
#import "OAuth+Additions.h"

#import "AFOAuth1Client.h"

#import <Accounts/Accounts.h>

#define NSNullIfNil(v) (v ? v : [NSNull null])


@interface SHOmniAuthTwitter ()
+(NSMutableDictionary *)authHashWithResponse:(NSDictionary *)theResponse;

@end

// from AFOAuth1Client
static NSDictionary * AFParametersFromQueryString(NSString *queryString) {
    NSMutableDictionary *parameters = [NSMutableDictionary dictionary];
    if (queryString) {
        NSScanner *parameterScanner = [[NSScanner alloc] initWithString:queryString];
        NSString *name = nil;
        NSString *value = nil;
        
        while (![parameterScanner isAtEnd]) {
            name = nil;
            [parameterScanner scanUpToString:@"=" intoString:&name];
            [parameterScanner scanString:@"=" intoString:NULL];
            
            value = nil;
            [parameterScanner scanUpToString:@"&" intoString:&value];
            [parameterScanner scanString:@"&" intoString:NULL];
            
            if (name && value) {
                parameters[[name stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding]] = [value stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
            }
        }
    }
    
    return parameters;
}


@implementation SHOmniAuthTwitter

+(void)performLoginWithListOfAccounts:(SHOmniAuthAccountsListHandler)accountPickerBlock
                           onComplete:(SHOmniAuthAccountResponseHandler)completionBlock; {
  ACAccountStore * accountStore  =  [[ACAccountStore alloc] init];
  ACAccountType  * accountType   = [accountStore accountTypeWithAccountTypeIdentifier:self.accountTypeIdentifier];
  [accountStore requestAccessToAccountsWithType:accountType options:nil completion:^(BOOL granted, NSError *error) {
    dispatch_async(dispatch_get_main_queue(), ^{
      accountPickerBlock([accountStore accountsWithAccountType:accountType], ^(id<account> theChosenAccount) {
        if (granted
            // No account, we should attempt to create one with performLoginForNewAccount
            || ([error.domain isEqualToString:ACErrorDomain] && error.code == 6 && theChosenAccount == nil)
            // Access not granted, no account, we should attempt to create one (or login otherwise) with performLoginForNewAccount
            || (!granted && theChosenAccount == nil)) {
          ACAccount * account = (ACAccount *)theChosenAccount;
          if(account == nil)[self performLoginForNewAccount:completionBlock granted:granted];
          else [self performReverseAuthForAccount:account withBlock:completionBlock];
        }
        // Access not granted
        else if (!granted) {
            NSError *responseError = [NSError errorWithDomain:kOmniAuthTwitterErrorDomainAccessNotGranted code:kOmniAuthTwitterErrorCodeAccessNotGranted userInfo:@{NSLocalizedDescriptionKey : @"To use your Twitter account with this app, open Settings > Twitter and make sure this app is turned on."}];
            completionBlock(nil, nil, responseError, granted);
        }
        // Other error
        else {
            completionBlock(nil, nil, error, granted);
        }
      });
    });
  }];
  
  
}

+(void)performLoginForNewAccount:(SHOmniAuthAccountResponseHandler)completionBlock granted: (BOOL) granted {
  
  
  
  
  AFOAuth1Client *  twitterClient = [[AFOAuth1Client alloc]
                                     initWithBaseURL:[NSURL URLWithString:@"https://api.twitter.com/"]
                                     key:[SHOmniAuth providerValue:SHOmniAuthProviderValueKey forProvider:self.provider]
                                     secret:[SHOmniAuth providerValue:SHOmniAuthProviderValueSecret forProvider:self.provider]];
  
  [twitterClient authorizeUsingOAuthWithRequestTokenPath:@"oauth/request_token"
                                   userAuthorizationPath:@"oauth/authorize"
                                             callbackURL:[NSURL
                                                          URLWithString:[SHOmniAuth
                                                                         providerValue:SHOmniAuthProviderValueCallbackUrl
                                                                         forProvider:self.provider]]
                                         accessTokenPath:@"oauth/access_token"
                                            accessMethod:@"POST"
                                                   scope:[SHOmniAuth
                                                          providerValue:SHOmniAuthProviderValueScope
                                                          forProvider:self.provider]
                                                success:^(AFOAuth1Token *accessToken, id responseObject) {
                                                    if (granted) {
                                                        NSString *responseString = [[NSString alloc] initWithData:responseObject encoding:NSUTF8StringEncoding];
                                                        NSString *screenName = [AFParametersFromQueryString(responseString) valueForKey:@"screen_name"];
                                                        
                                                        [self saveTwitterAccountWithToken:accessToken.key andSecret:accessToken.secret andScreenName:screenName 
                                                        withCompletionHandler:^(ACAccount *account, NSError *error) {
                                                            if(account) {
                                                                [self performReverseAuthForAccount:account withBlock:completionBlock];
                                                            }
                                                            else {
                                                                completionBlock(nil, nil, error, NO);
                                                            }
                                                        }];
                                                    }
                                                    else {
                                                        // Convert responseObject to string and dictionary from OAuth response
                                                        NSString *responseString = [responseObject isKindOfClass:[NSData class]] ? [[NSString alloc] initWithData:responseObject encoding:NSUTF8StringEncoding] : nil;
                                                        NSDictionary *response = responseString ? [NSURL ab_parseURLQueryString: responseString] : @{};
                                                        
                                                        completionBlock(nil, response, nil, YES);
                                                    }
                                                 } failure:^(NSError *error) {
                                                   completionBlock(nil, nil, error, NO);
                                                 }];
}

+(BOOL)hasLocalAccountOnDevice; {
  return [TWAPIManager isLocalTwitterAccountAvailable];
}


+(void)performReverseAuthForAccount:(ACAccount *)theAccount withBlock:(SHOmniAuthAccountResponseHandler)completionBlock; {
  [TWAPIManager registerTwitterAppKey:[SHOmniAuth providerValue:SHOmniAuthProviderValueKey forProvider:self.provider]
                         andAppSecret:[SHOmniAuth providerValue:SHOmniAuthProviderValueSecret forProvider:self.provider]];
  
  
  ACAccountStore * accountStore  =  [[ACAccountStore alloc] init];
  ACAccountType  * accountType   = [accountStore accountTypeWithAccountTypeIdentifier:self.accountTypeIdentifier];
  theAccount.accountType = accountType; // Apple SDK bug - accountType isn't retained.
  [TWAPIManager performReverseAuthForAccount:theAccount withHandler:^(NSData *responseData, NSError *error) {
    
    if(responseData == nil) {
      dispatch_async(dispatch_get_main_queue(), ^{
        completionBlock((id<account>)theAccount, nil, error, NO);
        return;
      });
    }
    
    NSString *responseStr = [[NSString alloc] initWithData:responseData encoding:NSUTF8StringEncoding];
    
    
    NSDictionary * response = [NSURL ab_parseURLQueryString:responseStr];
    
    
    
    
    BOOL isSuccess = error == nil ? YES : NO;
    
    SLRequest * request = [SLRequest requestForServiceType:SLServiceTypeTwitter requestMethod:SLRequestMethodGET URL:[NSURL URLWithString:@"https://api.twitter.com/1.1/account/verify_credentials.json?include_entities=false&skip_status=true"] parameters:nil];
    request.account = theAccount;
    
    [request performRequestWithHandler:^(NSData *responseData, NSHTTPURLResponse *urlResponse, NSError *error) {
      
      
      if(responseData == nil) {
        dispatch_async(dispatch_get_main_queue(), ^{
          completionBlock((id<account>)theAccount, nil, error, NO);
          return;
        });
      }
      
        NSDictionary * responseUser = nil;
        NSError *jsonError = nil;
        
        if (responseData != nil) {
            responseUser = [NSJSONSerialization JSONObjectWithData:responseData options:NSJSONReadingAllowFragments error:&jsonError];
        }
        
      NSMutableDictionary * fullResponse = responseUser.mutableCopy;
      fullResponse[@"oauth_token_secret"] = NSNullIfNil(response[@"oauth_token_secret"]);
      fullResponse[@"oauth_token"]        = NSNullIfNil(response[@"oauth_token"]);
      
      dispatch_async(dispatch_get_main_queue(), ^{
        if (responseUser == nil) {
          NSString * message = @"Bad response: Unknown error"; // Default message
          
          if (responseData) message = [[NSString alloc] initWithData: responseData encoding:NSUTF8StringEncoding];
          
          
          NSError *responseError = [NSError errorWithDomain:kOmniAuthTwitterErrorDomain
                                                       code:urlResponse.statusCode
                                                   userInfo:@{NSLocalizedDescriptionKey : NSNullIfNil(message)}];
          
          completionBlock((id<account>)theAccount, nil, responseError, NO);
        }
        // Twitter response may contain errors and should not be propagated to completionBlock or authHashWithResponse
        else if ([responseUser[@"errors"] count] > 0) {
          NSError *responseError = nil;
          NSDictionary *responseErrorDictionary = responseUser[@"errors"][0];
          NSInteger code = [responseErrorDictionary[@"code"] integerValue];
          NSString *message = responseErrorDictionary[@"message"];
          responseError = [NSError errorWithDomain:kOmniAuthTwitterErrorDomain code:code userInfo:@{NSLocalizedDescriptionKey : NSNullIfNil(message)}];
          completionBlock((id<account>)theAccount, nil, responseError, NO);
        }
        else completionBlock((id<account>)theAccount, [self authHashWithResponse:fullResponse.copy], error, isSuccess);
        
      });
      
    }];
    
  }];
  
  
}

+(void)saveTwitterAccountWithToken:(NSString *)theToken andSecret:(NSString *)theSecret andScreenName:(NSString *)screenName
             withCompletionHandler:(void (^)(ACAccount * account, NSError * error))onCompletionBlock; {
  
  ACAccountStore * accountStore  =  [[ACAccountStore alloc] init];
  ACAccountType  * accountType   = [accountStore accountTypeWithAccountTypeIdentifier:self.accountTypeIdentifier];
  
  ACAccountCredential * credential    = [[ACAccountCredential alloc]
                                         initWithOAuthToken:theToken tokenSecret:theSecret];
  
  __block ACAccount * account = [[ACAccount alloc]
                                 initWithAccountType:accountType];
  account.accountType = accountType; // Apple SDK bug - accountType isn't retained.
  
  account.credential = credential;
    
    if (screenName) {
      account.username = screenName;
    }
    
    BOOL overrideExistingAccount = YES;
    
    typedef void (^OriginalSaveAccountFinishedBlock)(BOOL success, NSError *error, BOOL canOverrideExistingAccount);
    typedef void (^SaveAccountFinishedBlock)(BOOL success, NSError *error, BOOL canOverrideExistingAccount, OriginalSaveAccountFinishedBlock finishedBlock);
    
    SaveAccountFinishedBlock saveAccountFinishedBlock = ^(BOOL success
                                                          , NSError *error, BOOL canOverrideExistingAccount, OriginalSaveAccountFinishedBlock finishedBlock) {
        BOOL finished = YES;
        
        if ([error.domain isEqualToString:ACErrorDomain] && error.code == ACErrorAccountAlreadyExists) {
            NSArray * accounts = [accountStore accountsWithAccountType:accountType];
            
            ACAccount *matchingAccount = nil;
            
            if (canOverrideExistingAccount) {
                // Find matching account
                for (ACAccount *acct in accounts) {
                    if ([acct.accountType.identifier isEqualToString: account.accountType.identifier] && [acct.username isEqualToString: account.username]) {
                        matchingAccount = acct;
                        break;
                    }
                }
            }
            
            // Override and remove existing account
            if (matchingAccount != nil && canOverrideExistingAccount) {
                finished = NO;
                // Remove account
                [accountStore removeAccount:matchingAccount withCompletionHandler:^(BOOL success, NSError *error) {
                    // Successful
                    if (success && !error) {
                        [accountStore saveAccount:account withCompletionHandler:^(BOOL success, NSError *error) {
                            if (finishedBlock != nil) {
                                finishedBlock(success, error, overrideExistingAccount);
                            }
                        }];
                    }
                    // Failure
                    else {
                        onCompletionBlock(nil, error);
                    }
                }];
            }
            else {
                // Only return an account if we're sure the account is the matching account
                if(accounts.count == 1)
                    account = accounts[0];
                else if (accounts.count > 1) {
                    error = [NSError errorWithDomain:kOmniAuthTwitterErrorDomainConflictingAccounts code:kOmniAuthTwitterErrorCodeConflictingAccounts userInfo:@{NSLocalizedDescriptionKey : @"Could not save account: Conflicting accounts because there is more than a single twitter account."}];
                    account = nil;
                }
                else {
                    account = nil;
                }
            }
        
        }
        
        else if (success == NO) account = nil;
        
        if (finished) {
            dispatch_async(dispatch_get_main_queue(), ^{ onCompletionBlock(account, error); });
        }
    };
    
    [accountStore saveAccount:account withCompletionHandler:^(BOOL success, NSError *error) {
        saveAccountFinishedBlock(success, error, overrideExistingAccount, ^(BOOL success, NSError *error, BOOL canOverrideExistingAccount) {
            saveAccountFinishedBlock(success, error, NO, NULL);
        });
    }];
}


+(NSString *)provider; {
  return self.description;
}

+(NSString *)accountTypeIdentifier; {
  return ACAccountTypeIdentifierTwitter;
}

+(NSString *)serviceType; {
  return SLServiceTypeTwitter;
}

+(NSString *)description; {
  return NSStringFromClass(self.class);
}
+(NSMutableDictionary *)authHashWithResponse:(NSDictionary *)theResponse; {
  NSString * name  = theResponse[@"name"];
  NSArray  * names = [name componentsSeparatedByString:@" "];
  NSString * firstName = nil;
  NSString * lastName = nil;
  if(names.count > 0 )
    firstName = names[0];
  if(names.count > 1 )
    lastName = names[1];
  if(names.count > 2 )
    lastName = names[names.count-1];
   
  NSString * screenName = theResponse[@"screen_name"];
  
  // To avoid (null) in string
  if (!screenName) {
    screenName = @"";
  }
    
  NSString * publicProfile = [@"https://twitter.com" stringByAppendingPathComponent: screenName];
    
  NSMutableDictionary * omniAuthHash = @{@"auth" :@{
                                             @"credentials" : @{@"secret" : NSNullIfNil(theResponse[@"oauth_token_secret"]),
                                                                @"token"  : NSNullIfNil(theResponse[@"oauth_token"])
                                                                }.mutableCopy,
                                             
                                             @"info"        : @{@"description" : NSNullIfNil(theResponse[@"description"]),
                                                                @"email"       : NSNullIfNil(theResponse[@"email"]),
                                                                @"first_name"  : NSNullIfNil(firstName),
                                                                @"last_name"   : NSNullIfNil(lastName),
                                                                @"headline"    : NSNullIfNil(theResponse[@"headline"]),
                                                                @"image"       : NSNullIfNil(theResponse[@"profile_image_url"]),
                                                                @"name"        : NSNullIfNil(name),
                                                                @"urls"        : @{@"public_profile" : publicProfile,
                                                                                   @"website" : NSNullIfNil(theResponse[@"url"])
                                                                                   }.mutableCopy,
                                                                
                                                                }.mutableCopy,
                                             
                                             @"provider" : @"twitter",
                                             @"uid"      : NSNullIfNil(theResponse[@"id"]),
                                             @"raw_info" : NSNullIfNil(theResponse)
                                             }.mutableCopy,
                                         @"email"    : NSNullIfNil(theResponse[@"email"]),
                                         }.mutableCopy;
  
  
  return omniAuthHash;
}
@end
