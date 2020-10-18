Pod::Spec.new do |spec|
  spec.name         = "LCWebSocket"
  spec.version      = "0.0.1"
  spec.summary      = "WebSocket client in Objective-C."
  spec.homepage     = "https://github.com/leancloud/LCWebSocket"
  spec.license      = { :type => "MIT", :file => "LICENSE" }
  spec.author       = { "zapcannon87" => "zapcannon87@outlook.com" }

  spec.ios.deployment_target = "9.0"
  spec.osx.deployment_target = "10.10"

  spec.source              = { :git => "https://github.com/leancloud/LCWebSocket.git", :tag => "#{spec.version}" }
  spec.source_files        = "LCWebSocket/**/*.{h,m}"
  spec.public_header_files = "LCWebSocket/**/*.h"
end
