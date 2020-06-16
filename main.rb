require 'yaml'
require 'json'
require 'open3'
require 'pathname'
require 'plist'
require 'fileutils'
require 'uri'
require 'xcodeproj'
require 'securerandom'

###### Enviroment Variable Check
def env_has_key(key)
	return (ENV[key] != nil && ENV[key] !="") ? ENV[key] : abort("Missing #{key}.")
end

$temporary_path = env_has_key("AC_TEMP_DIR")
$temporary_path += "/appcircle_export_archive"
$output_path = env_has_key("AC_OUTPUT_DIR")
$project_path = env_has_key("AC_PROJECT_PATH")
$scheme = env_has_key("AC_SCHEME")
$repository_path = ENV["AC_REPOSITORY_DIR"]

$project_full_path = $repository_path ? (Pathname.new $repository_path).join($project_path) : $project_path

$configuration_name = (ENV["AC_CONFIGURATION_NAME"] != nil && ENV["AC_CONFIGURATION_NAME"] !="") ? ENV["AC_CONFIGURATION_NAME"] : nil

#compiler_index_store_enable - Options: YES, NO
$compiler_index_store_enable = env_has_key("AC_COMPILER_INDEX_STORE_ENABLE")

#method_for_export - Options: auto-detect, development, enterprise, ad-hoc, app-store
$method_for_export = (ENV["AC_METHOD_FOR_EXPORT"] != nil && ENV["AC_METHOD_FOR_EXPORT"] !="") ? ENV["AC_METHOD_FOR_EXPORT"] : "auto-detect"

$teamid_for_export = (ENV["AC_TEAMID_FOR_EXPORT"] != nil && ENV["AC_TEAMID_FOR_EXPORT"] !="") ? ENV["AC_TEAMID_FOR_EXPORT"] : nil

#compile_bitcode_for_export - Options: YES, NO
$compile_bitcode_for_export = (ENV["AC_COMPILE_BITCODE_FOR_EXPORT"] != nil && ENV["AC_COMPILE_BITCODE_FOR_EXPORT"] !="") ? ENV["AC_COMPILE_BITCODE_FOR_EXPORT"] : nil

#upload_bitcode_for_export - Options: YES, NO
$upload_bitcode_for_export = (ENV["AC_UPLOAD_BITCODE_FOR_EXPORT"] != nil && ENV["AC_UPLOAD_BITCODE_FOR_EXPORT"] !="") ? ENV["AC_UPLOAD_BITCODE_FOR_EXPORT"] : nil

#upload_symbols_for_export - Options: YES, NO
$upload_symbols_for_export = (ENV["AC_UPLOAD_SYMBOLS_FOR_EXPORT"] != nil && ENV["AC_UPLOAD_SYMBOLS_FOR_EXPORT"] !="") ? ENV["AC_UPLOAD_SYMBOLS_FOR_EXPORT"] : nil

#icloudcontainerenvironment_for_export - Options: Development, Production
$icloudcontainerenvironment_for_export = (ENV["AC_ICLOUD_CONTAINER_ENVIRONMENT_FOR_EXPORT"] != nil && ENV["AC_ICLOUD_CONTAINER_ENVIRONMENT_FOR_EXPORT"] !="") ? ENV["AC_ICLOUD_CONTAINER_ENVIRONMENT_FOR_EXPORT"] : nil

$extra_options = []

if ENV["AC_ARCHIVE_FLAGS"] != "" && ENV["AC_ARCHIVE_FLAGS"] != nil
  $extra_options = ENV["AC_ARCHIVE_FLAGS"].split("|")
end

$archive_path = "#{$output_path}/build.xcarchive"
$metadata_path = "#{$output_path}/build_metadata.json"

$is_workspace = false
if File.extname($project_path) == ".xcworkspace"
  $is_workspace = true
end

$is_sign_available = true
# AC_CERTIFICATES
# "password|/Users/..|password|/Users/.."
if  ENV["AC_CERTIFICATES"] == nil || ENV["AC_CERTIFICATES"] ==""
  puts "Doesn't Sign : Missing AC_CERTIFICATES."
  $is_sign_available = false
else
  $certificates = ENV["AC_CERTIFICATES"]
end


# AC_PROVISIONING_PROFILES
if  ENV["AC_PROVISIONING_PROFILES"] == nil || ENV["AC_PROVISIONING_PROFILES"] ==""
  puts "Doesn't Sign : Missing AC_PROVISIONING_PROFILES."
  $is_sign_available = false
else
  $provisioning_profiles = ENV["AC_PROVISIONING_PROFILES"]
end

# AC_BUNDLE_IDENTIFIERS
if  ENV["AC_BUNDLE_IDENTIFIERS"] == nil || ENV["AC_BUNDLE_IDENTIFIERS"] ==""
  puts "Doesn't Sign : Missing AC_BUNDLE_IDENTIFIERS."
  $is_sign_available = false
else
  $bundle_identifiers = ENV["AC_BUNDLE_IDENTIFIERS"]
end

###### Run Command Function
def run_command(command,skip_abort)
  puts "@[command] #{command}"
  status = nil
  stdout_str = nil
  stderr_str = nil
  Open3.popen3(command) do |stdin, stdout, stderr, wait_thr|
    stdout.each_line do |line|
      puts line
    end
    stdout_str = stdout.read
    stderr_str = stderr.read
    status = wait_thr.value
  end

  unless status.success?
    if skip_abort
      puts stderr_str
    else
      abort_script(stderr_str)
    end
  end
end

def abort_script(error)
  if $is_sign_available
    remove_keychain_provisioning_profile()
  end
  abort("#{error}")
end

###### Import Certificate & Provisioning
def create_keychain()
  keychain_path = "#$temporary_path/#{SecureRandom.uuid}.keychain"
  keychain_password = [*('a'..'z'),*('0'..'9')].shuffle[0,16].join

  command_create_keychain = "security create-keychain -p #{keychain_password} \"#{keychain_path}\""
    run_command(command_create_keychain,false)
  
    command_set_settings = "security set-keychain-settings \"#{keychain_path}\""
    run_command(command_set_settings,false)
  
    command_unlock_keychain = "security unlock-keychain -p #{keychain_password} \"#{keychain_path}\""
    run_command(command_unlock_keychain,false)

    command_list = "security list-keychain -d user"
    run_command(command_list,false)
  
    command_list_s = "security list-keychain -d user -s $(security list-keychains -d user | sed -e s/\\\"//g) \"#{keychain_path}\""
    run_command(command_list_s,false)
  
    command_list2 = "security list-keychain -d user"
  run_command(command_list2,false)
  
  return keychain_path,keychain_password
end

def import_certificate(keychain_path)
  cert_string = $certificates

  cert_array = []
  split_cert_string = cert_string.split("|")
  
  split_cert_length = split_cert_string.length
  x = 0
  while x < split_cert_length
      cert = {"certificate" => "#{split_cert_string[x+1]}", "password"=> "#{split_cert_string[x]}"}
    cert_array.push(cert)
    x += 2
  end

  cert_array.each_with_index do |data,index|
    command_import_certificate = "security import #{data["certificate"]} -P \"#{data["password"]}\" -A -t cert -f pkcs12 -k \"#{keychain_path}\""
    run_command(command_import_certificate,false)
  end

  return cert_array
end

def import_provisioning_profile()
  provisioning_profiles_string = $provisioning_profiles
  bundle_identifiers_string = $bundle_identifiers

  provisioning_profile_array = provisioning_profiles_string.split("|")
  bundle_identifiers_array = bundle_identifiers_string.split("|")

  bundle_provisioning_object_array = []

  provisioning_profile_array.each_with_index do |profile,index|
    profile = {"bundleIdentifier" => "#{bundle_identifiers_array[index]}", "provisioningProfile"=> "#{profile}"}
    bundle_provisioning_object_array.push(profile)
  end

  unless File.directory?(ENV['HOME'] + '/Library/MobileDevice')
    FileUtils.mkdir_p ENV['HOME']+'/Library/MobileDevice/Provisioning Profiles'
  end
  
  bundle_provisioning_object_array.each_with_index do |data,index|
  
    provisioning_profile_plist = "#{File.dirname(data["provisioningProfile"])}/_xcodeprovisioningprofiletmp.plist"
    command_cms = "security cms -D -i #{data["provisioningProfile"]}"
    run_command(command_cms,false)
    run_command("#{command_cms} > #{provisioning_profile_plist}",false)
  
    command_uuid = "/usr/libexec/PlistBuddy -c \"Print UUID\" \"#{provisioning_profile_plist}\""
    puts command_uuid
    uuid = `#{command_uuid}`.chomp
    puts uuid
  
    command_copy = "cp -f #{data["provisioningProfile"]} ~/Library/MobileDevice/Provisioning\\ Profiles/#{uuid}.mobileprovision"
    run_command(command_copy,false)
    
    bundle_provisioning_object_array[index]["uuid"] = uuid
  
  end
  
  puts "Provisioning Profiles : #{bundle_provisioning_object_array}"

  return bundle_provisioning_object_array
end

### Remove Certificate & Provisioning
def remove_keychain(keychain_path)
  command_delete = "security delete-keychain \"#{keychain_path}\""
  run_command(command_delete,true)
end

def remove_provisioning_profiles(provisioning_profile_array)
  provisioning_profile_array.each do |data|
    path = "~/Library/MobileDevice/Provisioning\\ Profiles/#{data["uuid"]}.mobileprovision"
    command_delete = "rm -f #{path}"
    run_command(command_delete,true)
  end
end

def remove_keychain_provisioning_profile()
  if $keychain_path != nil
    remove_keychain($keychain_path)
  end
  
  if $bundle_identifiers_provisioning_profiles != nil
    remove_provisioning_profiles($bundle_identifiers_provisioning_profiles)
  end
end

###### Update Build Settings With Code Sign
def update_build_settings()
  begin
    manualProvisioningProfilePlist = "_xcodeManualProvisioningProfiletmp.plist"
    command_read_certificate = "openssl pkcs12 -in #{$certificate_array[0]["certificate"]} -nokeys -passin pass:\"#{$certificate_array[0]["password"]}\" | openssl x509 -noout -subject"
    puts command_read_certificate
    certificate_description_string, stderr_str, status = Open3.capture3(command_read_certificate)
    unless status.success?
      raise stderr_str
    end

    certificate_description_splitted = certificate_description_string.split("/")
    certificate_description_splitted.each { |item| 
      item_splitted = item.split("=")
      key = item_splitted[0]
      value = item_splitted[1]

      if key == "CN"
        $code_sign_identity = value
      elsif key == "OU"
        $code_sign_development_team = value
      end
    }

    proj_path = get_project_path
    xcproj = Xcodeproj::Project.open(proj_path)

    $bundle_identifiers_provisioning_profiles.each_with_index do |data, index|

      xcproj.native_targets.each { |target| 
        if data["bundleIdentifier"] == get_bundle_identifier(target)
          command_provisioning_plist = "security cms -D -i #{data["provisioningProfile"]} > #{File.dirname(data["provisioningProfile"])}/_#{index}#{manualProvisioningProfilePlist}"
          run_command(command_provisioning_plist,true);
          provisioning_plist = Plist.parse_xml("#{File.dirname(data["provisioningProfile"])}/_#{index}#{manualProvisioningProfilePlist}")

          target.build_configurations.each do |item|
            item.build_settings['CODE_SIGN_IDENTITY'] = $code_sign_identity
          end

          target.build_configurations.each do |item|
            item.build_settings['CODE_SIGN_IDENTITY[sdk=iphoneos*]'] = $code_sign_identity
          end 
          
          target.build_configurations.each do |item|
            item.build_settings['PROVISIONING_PROFILE'] = provisioning_plist['UUID']
          end

          target.build_configurations.each do |item|
            item.build_settings['PROVISIONING_PROFILE[sdk=iphoneos*]'] = provisioning_plist['UUID']
          end

          target.build_configurations.each do |item|
            item.build_settings['CODE_SIGN_STYLE'] = "Manual"
          end

          target.build_configurations.each do |item|
            item.build_settings['DEVELOPMENT_TEAM'] = $code_sign_development_team
          end

          puts "\n"

          puts "Bundle Identifier : #{data["bundleIdentifier"]}"
          puts "Code Sign Identity : #{$code_sign_identity}"
          puts "Provisioning Profile : #{provisioning_plist['UUID']}"
          puts "Development Team : #{$code_sign_development_team}"
          puts "Code Sign Style : Manual"

          puts "\n"

        end
      }

    end

    xcproj.save

  rescue Exception => e
    abort_script(e)
  end
end

def get_bundle_identifier(target)
    return target.build_configuration_list.build_settings(target.build_configuration_list.default_configuration_name)["PRODUCT_BUNDLE_IDENTIFIER"]
end

def get_project_path
  if $is_workspace
    begin
      workspace = Xcodeproj::Workspace.new_from_xcworkspace($project_full_path)
      workspace.file_references.each do |file|

        file_full_path = (Pathname.new File.dirname($project_full_path)).join(file.path)
        command_read_schemes = "xcodebuild -project \"#{file_full_path}\" -list"
        puts command_read_schemes
        schemes_string, stderr_str, status = Open3.capture3(command_read_schemes)
        unless status.success?
        	puts stderr_str
          raise stderr_str
        end
        puts schemes_string
        schemes_string_siplitted = schemes_string.split('Schemes:')[1]
        if schemes_string_siplitted.include? $scheme
          return file_full_path
        end
      end
    rescue Exception => e
      abort_script(e)
    end
  else
    return $project_full_path
  end
end

###### Export Options & Export Archive
def generate_export_options()
  expOptProvisioningProfilePlist = "_xcodeExpOptProvisioningProfiletmp.plist"
  exportOptionsPlist = "_xcodeExportOptionstmp.plist"
  export_options = {}

  ######Provisioning Profile
  applications_path = "#{$archive_path}/Products/Applications"
  bundle_identifiers, provisioning_profiles = get_bundle_identifiers_and_embedded_provisioning_profiles(applications_path)

  provisioning_profile_object = {}
  application_profile_plist = nil
  provisioning_profiles.each_with_index do |data, index|
    command_provisioning_plist = "security cms -D -i \"#{data}\" > \"#{$temporary_path}/_#{index}#{expOptProvisioningProfilePlist}\""
    run_command(command_provisioning_plist,false);
  
    provisioning_plist = Plist.parse_xml("#{$temporary_path}/_#{index}#{expOptProvisioningProfilePlist}")
    if index == 0
      application_profile_plist = provisioning_plist
    end
    provisioning_profile_object[bundle_identifiers[index]] = provisioning_plist['UUID']
  end
  export_options['provisioningProfiles'] = provisioning_profile_object
  #####################


  export_options['signingStyle'] = :manual
  export_options['destination'] = :export
  
  if $method_for_export == 'auto-detect'
    if application_profile_plist['Entitlements']['get-task-allow']
      export_options['method'] = "development"
    elsif application_profile_plist['ProvisionsAllDevices']
      export_options['method'] = "enterprise"
    elsif application_profile_plist['ProvisionedDevices']
      export_options['method'] = "ad-hoc"
    else
      export_options['method'] = "app-store"
    end
  else
    export_options['method'] = $method_for_export
  end
  
  if $teamid_for_export != nil
    export_options['teamID'] = $teamid_for_export
  end
  # export_options['teamID'] = application_profile_plist['TeamIdentifier'][0]

  unless export_options['method'] == "app-store"
    if $compile_bitcode_for_export == "YES"
      export_options['compileBitcode'] = true
    elsif $compile_bitcode_for_export == "NO"
      export_options['compileBitcode'] = false
    end
    if $icloudcontainerenvironment_for_export != nil
      export_options['iCloudContainerEnvironment'] = $icloudcontainerenvironment_for_export
    end
  else
    if $upload_bitcode_for_export == "YES"
      export_options['uploadBitcode'] = true
    elsif $upload_bitcode_for_export == "NO"
      export_options['uploadBitcode'] = false
    end
    if $upload_symbols_for_export == "YES"
      export_options['uploadSymbols'] = true
    elsif $upload_symbols_for_export == "NO"
      export_options['uploadSymbols'] = false
    end
  end

  puts "\nExport Options : \n#{export_options}\n\n"
  plist_path = "#{$temporary_path}/#{exportOptionsPlist}"
  export_options.save_plist(plist_path)
  
  return plist_path
end

def export_archive(export_options)
  command_export = "xcodebuild -exportArchive -archivePath \"#$archive_path\" -exportPath \"#$output_path\" -exportOptionsPlist \"#{export_options}\""
  run_command(command_export,false);

  begin
    #Write Environment Variable
    open(ENV['AC_ENV_FILE_PATH'], 'a') { |f|
      f.puts "AC_EXPORT_DIR=#$output_path"
    }
  rescue Exception => e
    abort_script(e)
  end
end

### Archive Functions
def archive()
  extname = File.extname($project_path)
  command = "xcodebuild -scheme \"#{$scheme}\" clean archive -archivePath \"#{$archive_path}\" -derivedDataPath \"#{$temporary_path}/DerivedData\""
  
  if $is_sign_available
    command.concat(" ")
    command.concat("CODE_SIGN_STYLE=Manual")
    command.concat(" ")
  else
    command.concat(" ")
    command.concat("CODE_SIGN_IDENTITY=\"\" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO")
    command.concat(" ")
  end

  if $configuration_name != nil
    command.concat(" ")
    command.concat("-configuration \"#{$configuration_name}\"")
    command.concat(" ")
  end

  if $compiler_index_store_enable != nil
    command.concat(" ")
    command.concat("COMPILER_INDEX_STORE_ENABLE=#{$compiler_index_store_enable}")
    command.concat(" ")
  end

  if $extra_options.kind_of?(Array)
    $extra_options.each do |option|
      command.concat(" ")
      command.concat(option)
      command.concat(" ")
    end
  end

  if $is_workspace
    command.concat(" -workspace \"#{$project_full_path}\"")
  else
    command.concat(" -project \"#{$project_full_path}\"")
  end


  run_command(command,false)
end

def get_bundle_identifiers_and_embedded_provisioning_profiles(path)
  identifiers = []
  embedded_provisioning_profiles = []
  Dir.chdir(path) do
    Dir.glob('*').select { |product| 
      plist = "#{product}/Info.plist"
      command_uuid = "/usr/libexec/PlistBuddy -c \"Print CFBundleIdentifier\" \"#{plist}\""
      identifier = `#{command_uuid}`.chomp
      identifiers << identifier

      if File.file?("#{product}/embedded.mobileprovision")
        embedded_provisioning_profiles  << "#{Dir.pwd}/#{product}/embedded.mobileprovision"
      else
        embedded_provisioning_profiles  << nil
      end

      if File.directory?("#{product}/PlugIns")
        ids, profiles = get_bundle_identifiers_and_embedded_provisioning_profiles("#{product}/PlugIns")
        identifiers.concat(ids)
        embedded_provisioning_profiles.concat(profiles)
      end
    }
  end
  return identifiers, embedded_provisioning_profiles
end

def generate_archive_metadata()
  bundle_identifiers = []
  if File.directory?($archive_path)
    applications_path = "#{$archive_path}/Products/Applications"
    bundle_identifiers.concat(get_bundle_identifiers_and_embedded_provisioning_profiles(applications_path)[0])
  else
    abort('Archive path not found.')
  end
  xcode_version = `xcodebuild -version`.split(' ')[1].chomp
  object = {"bundleIdentifiers" => bundle_identifiers, "xcodeVersion" => "#{xcode_version}", "scheme" => "#{$scheme}"}
  File.open("#{$metadata_path}","w") do |f|
    f.write(object.to_json)
  end
end

###############################################################

if $is_sign_available
  $keychain_path,$keychain_password = create_keychain()
  $certificate_array = import_certificate($keychain_path)
  $bundle_identifiers_provisioning_profiles = import_provisioning_profile()
  update_build_settings()
end

archive()
generate_archive_metadata()

if $is_sign_available
  export_options = generate_export_options()
  export_archive(export_options)
  remove_keychain_provisioning_profile()
end

###############################################################

### Write Environment Variable
open(ENV['AC_ENV_FILE_PATH'], 'a') { |f|
  f.puts "AC_ARCHIVE_METADATA_PATH=#{$metadata_path}"
  f.puts "AC_ARCHIVE_PATH=#{$archive_path}"
}

exit 0