# Appcircle Xcodebuild For Devices

This step builds your application for iOS devices in ARM architecture, which is required for the Share With Testers feature or any other means of iOS distribution.

Xcodebuild For Devices step will run Xcodebuild command for your application. Appcircle will use the parameters like project path, scheme and Xcode version specified in your build configuration to run your build.

Required Input Variables
- `$AC_SCHEME`: Specifies the project scheme for build.
- `$AC_PROJECT_PATH`: Specifies the project path. For example : ./appcircle.xcodeproj.


Optional Input Variables
- `$AC_REPOSITORY_DIR`: Specifies the cloned repository directory.
- `$AC_ARCHIVE_FLAGS`: Specifies the extra xcodebuild flag. For example : -configuration DEBUG
- `$AC_CERTIFICATES`: URLs of the Certificates.
- `$AC_BUNDLE_IDENTIFIERS`: Specifies the project bundle identifers.
- `$AC_PROVISIONING_PROFILES`: URLs of the Provisioning Profiles.
- `$AC_CONFIGURATION_NAME`: The configuration to use. You can overwrite it with this option.
- `$AC_COMPILER_INDEX_STORE_ENABLE`: You can disable the indexing during the build for faster build.
- `$AC_METHOD_FOR_EXPORT`: Describes how Xcode should export the archive. Available options auto-detect, app-store, ad-hoc, enterprise, development. Default is auto-detect.
- `$AC_TEAMID_FOR_EXPORT`: The Developer Portal team to use for this export. Defaults to the team used to build the archive.
- `$AC_COMPILE_BITCODE_FOR_EXPORT`: For non-App Store exports, should Xcode re-compile the app from bitcode? Available options YES, NO.
- `$AC_UPLOAD_BITCODE_FOR_EXPORT`: For App Store exports, should the package include bitcode?. Available options YES, NO.
- `$AC_UPLOAD_SYMBOLS_FOR_EXPORT`: For App Store exports, should the package include symbols?. Available options YES, NO.
- `$AC_ICLOUD_CONTAINER_ENVIRONMENT_FOR_EXPORT`: For non-App Store exports, if the app is using CloudKit, this configures the "com.apple.developer.icloud-container-environment" entitlement. Available options Development and Production.

Output Variables
- `$AC_ARCHIVE_PATH`: Archive path.
- `$AC_ARCHIVE_METADATA_PATH`: Archive metadata path.
- `$AC_EXPORT_DIR`: Specifies the directory that contains ipa, exportOptions.plist, and other exported files.
