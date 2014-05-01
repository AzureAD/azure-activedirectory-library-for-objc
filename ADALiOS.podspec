Pod::Spec.new do |s|
  s.name         = "ADALiOS"
  s.version      = "0.5.1-alpha"
  s.summary      = "The ADAL SDK for iOS gives you the ability to add Windows Azure Active Directory authentication to your application"

  s.description  = <<-DESC
                   The ADAL SDK for iOS gives you the ability to add Windows Azure Active Directory authentication to your application with just a few lines of additional code. Using our ADAL SDKs you can quickly and easily extend your existing application to all the employees that use Windows Azure AD and Active Directory on-premises using Active Directory Federation Services, including Office365 customers. This SDK gives your application the full functionality of Windows Azure AD, including industry standard protocol support for OAuth2, Web API integration, and two factor authentication support. Best of all, it’s FOSS (Free and Open Source Software) so that you can participate in the development process as we build these libraries.
                   DESC
  s.homepage     = "https://github.com/MSOpenTech/azure-activedirectory-library-for-ios"
  s.license      = { 
    :type => "Apache License, Version 2.0", 
    :file => "LICENSE.txt" 
  }
  s.authors      = { "Boris Vidolov" => "borisv@microsoft.com" }
  s.social_media_url   = "https://twitter.com/MSOpenTech"
  s.platform     = :ios, "6.0"
  s.source       = { 
    :git => "https://github.com/damienpontifex/azure-activedirectory-library-for-ios.git", 
    :tag => s.version.to_s
  }
  s.source_files = "ADALiOS/ADALiOS/**/*.{h,m}"
  s.resources    = "ADALiOS/ADALiOS/*.storyboard"
  s.preserve_paths = "ADALiOS/ADALiOS/**/*.{h,m}"
  s.requires_arc = true
end
