Pod::Spec.new do |s|
  s.name         = "ADALiOS"
  s.version      = "1.0.0"
  s.summary      = "The ADAL SDK for iOS gives you the ability to add Azure Identity authentication to your application"

  s.description  = <<-DESC
                   The ADAL SDK for Objective C gives you the ability to add support for Work Accounts to your iOS and OS X applications with just a few lines of additional code. This SDK gives your application the full functionality of Microsoft Azure AD, including industry standard protocol support for OAuth2, Web API integration with user level consent, and two factor authentication support.
                   DESC
  s.homepage     = "https://github.com/MSOpenTech/azure-activedirectory-library-for-ios"
  s.license      = { 
    :type => "Apache License, Version 2.0", 
    :file => "LICENSE.txt" 
  }
  s.authors      = { "Brandon Werner" => "brandwe@microsoft.com" }
  s.social_media_url   = "https://twitter.com/brandwe"
  s.platform     = :ios, "6.0"
  s.source       = { 
    :git => "git@github.com:AzureAD/azure-activedirectory-library-for-objc.git", 
    :tag => s.version.to_s
  }
  s.source_files = "ADALiOS/ADALiOS/**/*.{h,m}"
  s.resources    = "ADALiOS/ADALiOS/*.storyboard"
  s.preserve_paths = "ADALiOS/ADALiOS/**/*.{h,m}"
  s.requires_arc = true
end
