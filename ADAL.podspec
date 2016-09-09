Pod::Spec.new do |s|
  s.name         = "ADAL"
  s.module_name  = "ADAL"
  s.version      = "2.2.5"
  s.summary      = "The ADAL SDK for iOS gives you the ability to add Azure Identity authentication to your application"

  s.description  = <<-DESC
                   The Azure Identity Library for Objective C. This library gives you the ability to add support for Work Accounts to your iOS and OS X applications with just a few lines of additional code. This SDK gives your application the full functionality of Microsoft Azure AD, including industry standard protocol support for OAuth2, Web API integration with user level consent, and two factor authentication support.
                   DESC
  s.homepage     = "https://github.com/AzureAD/azure-activedirectory-library-for-objc"
  s.license      = { 
    :type => "MIT", 
    :file => "LICENSE.txt" 
  }
  s.authors      = { "Microsoft" => "nugetaad@microsoft.com" }
  s.social_media_url   = "https://twitter.com/azuread"
  s.platform     = :ios, :osx
  s.ios.deployment_target = "8.0"
  s.osx.deployment_target = "10.10"
  s.source       = { 
    :git => "https://github.com/AzureAD/azure-activedirectory-library-for-objc.git", 
    :tag => s.version.to_s
  }
  
  s.default_subspecs ='app-lib'
  
  s.prefix_header_file = "ADAL/src/ADAL.pch"
  s.header_dir = "ADAL"
  s.module_map = "ADAL/resources/mac/adal_mac.modulemap"
  
  s.subspec 'app-lib' do |app|
  	app.source_files = "ADAL/src/**/*.{h,m}"
  	app.ios.public_header_files = "ADAL/src/public/*.h","ADAL/src/public/ios/*.h"
  	app.osx.public_header_files = "ADAL/src/public/mac/*.h","ADAL/src/public/*.h"
  
  	app.ios.exclude_files = "ADAL/src/**/mac/*"
  		
  	app.osx.exclude_files = "ADAL/src/**/ios/*"
  	app.osx.resources = "ADAL/resources/mac/ADCredentialViewController.xib"
  	
  	app.requires_arc = true
  	
  	app.ios.dependency 'ADAL/tokencacheheader'
  end
  
  # This is a hack because one of the headers is public on mac but private on ios
  s.subspec 'tokencacheheader' do |ph|
  	ph.platform = :ios
  	ph.ios.source_files = "ADAL/src/public/mac/ADTokenCache.h"
  	# This extra nonsense is so that it doesn't make ADTokenCache.h a public header on iOS
  	# And also doesn't generate a podspec warning
  	ph.ios.private_header_files = "ADAL/src/public/mac/ADTokenCache.h"
  end
  
  # Note, ADAL has limited support for running in app extensions.
  s.subspec 'extension' do |ext|
  	ext.compiler_flags = '-DADAL_EXTENSION_SAFE=1'
  	ext.source_files = "ADAL/src/**/*.{h,m}"
  	ext.ios.public_header_files = "ADAL/src/public/*.h","ADAL/src/public/ios/*.h"
  	ext.osx.public_header_files = "ADAL/src/public/mac/*.h","ADAL/src/public/*.h"
  
  	# There is currently a bug in CocoaPods where it doesn't combine the public headers
  	# for both the platform and overall.
  	ext.ios.exclude_files = "ADAL/src/**/mac/*"
  	ext.osx.exclude_files = "ADAL/src/**/ios/*"
  	
  	ext.requires_arc = true
  	
  	ext.ios.dependency 'ADAL/tokencacheheader'
  end
end
