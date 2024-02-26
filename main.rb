require 'yaml'
require 'json'
require 'open3'
require 'pathname'
require 'plist'
require 'fileutils'
require 'uri'
require 'xcodeproj'
require 'securerandom'
require 'English'

###### Enviroment Variable Check
def env_has_key(key)
	return (ENV[key] != nil && ENV[key] !="") ? ENV[key] : abort("Missing #{key}.")
end

$temporary_path = env_has_key("AC_TEMP_DIR")
$temporary_path += "/appcircle_export_archive"
$output_path = env_has_key("AC_OUTPUT_DIR_PATH")
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
$is_automatic_sign = false

if ENV["AC_AUTOSIGN_KEY"] != nil && ENV["AC_AUTOSIGN_KEY"] != ""
  puts "Using automatic code signing"
  $is_automatic_sign = true
end

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

# Certificate and provision profile map
$compatible_sign_files = {}

###### Run Command Function
def run_command(command,skip_abort)
  puts "@@[command] #{command}"
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

def run_command_simple(command)
  puts "@@[command] #{command}"
  stderr_file = "#{ENV['AC_TEMP_DIR']}/.command.stderr.log"
  command.concat(' 2>')
  command.concat(stderr_file)
  return if system(command)

  exit_code = $CHILD_STATUS.exitstatus
  system("cat #{stderr_file}")
  abort_script("@@[error] Unexpected exit with code #{exit_code}. Check logs for details.")
end

def abort_script(error)
  abort("#{error}")
end

###### Import Certificate & Provisioning
def parse_certificate()
  cert_string = $certificates

  cert_props = {}
  split_cert_string = cert_string.split("|")
  
  split_cert_length = split_cert_string.length
  x = 0
  while x < split_cert_length
    certificate = "#{split_cert_string[x+1]}"
    password = "#{split_cert_string[x]}"
    command_read_certificate = "openssl pkcs12 -in #{certificate} -nokeys -passin pass:\"#{password}\" | openssl x509 -noout -subject"
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
    cert_props["#{certificate}"] = { :code_sign_identity => "#{$code_sign_identity}", :code_sign_development_team => "#{$code_sign_development_team}"}
    x += 2
  end

  if $teamid_for_export.nil?
    $teamid_for_export = $code_sign_development_team
  end

  return cert_props
end

def parse_provisioning_profile()
  provisioning_profiles_string = $provisioning_profiles
  bundle_identifiers_string = $bundle_identifiers

  provisioning_profile_array = provisioning_profiles_string.split("|")
  bundle_identifiers_array = bundle_identifiers_string.split("|")

  bundle_provisioning_object_array = []

  provisioning_profile_array.each_with_index do |profile,index|
    profile = {"bundleIdentifier" => "#{bundle_identifiers_array[index]}", "provisioningProfile"=> "#{profile}"}
    bundle_provisioning_object_array.push(profile)
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
    
    bundle_provisioning_object_array[index]["uuid"] = uuid
  
  end
  
  puts "Provisioning Profiles : #{bundle_provisioning_object_array}"

  return bundle_provisioning_object_array
end

###### Update Build Settings With Code Sign
def update_build_settings()
  begin
    manualProvisioningProfilePlist = "_xcodeManualProvisioningProfiletmp.plist"

    proj_path = get_project_path
    xcproj = Xcodeproj::Project.open(proj_path)

    $bundle_identifiers_provisioning_profiles.each_with_index do |data, index|
      provisioningProfile = data["provisioningProfile"]
      certificate = $compatible_sign_files[provisioningProfile]
      $certificate_props = $certificate_properties[certificate]

      $code_sign_identity = $certificate_props[:code_sign_identity]
      $code_sign_development_team = $certificate_props[:code_sign_development_team]
      puts "code_sign_identity: #{$code_sign_identity}"
      puts "code_sign_development_team: #{$code_sign_development_team}"
      xcproj.native_targets.each { |target| 
      	target.build_configurations.each { |configuration|
          config_bundle_id = configuration.resolve_build_setting("PRODUCT_BUNDLE_IDENTIFIER") 
          if data["bundleIdentifier"] == config_bundle_id or ( data["bundleIdentifier"].include?(".*") and config_bundle_id.match(/#{data["bundleIdentifier"]}/)) 
      			
            provisioning_plist_path = "#{File.dirname(provisioningProfile)}/_#{index}#{manualProvisioningProfilePlist}"
      			unless File.exist?(provisioning_plist_path)
      				command_provisioning_plist = "security cms -D -i #{provisioningProfile} > #{provisioning_plist_path}"
          			run_command(command_provisioning_plist,true);
      			end
          		provisioning_plist = Plist.parse_xml("#{provisioning_plist_path}")

              configuration.build_settings['CODE_SIGN_IDENTITY'] = $code_sign_identity
              configuration.build_settings['CODE_SIGN_IDENTITY[sdk=iphoneos*]'] = $code_sign_identity
              configuration.build_settings['PROVISIONING_PROFILE'] = provisioning_plist['UUID']
              configuration.build_settings['PROVISIONING_PROFILE[sdk=iphoneos*]'] = provisioning_plist['UUID']
              configuration.build_settings['PROVISIONING_PROFILE_SPECIFIER'] = provisioning_plist['Name']
              configuration.build_settings['CODE_SIGN_STYLE'] = "Manual"
              configuration.build_settings['DEVELOPMENT_TEAM'] = $code_sign_development_team

              puts "------------------------------------------------------"

              puts "Target Name : #{target.name}"
              puts "Target Build Configuration : #{configuration.name}"
              puts "Configuration Bundle Identifier : #{configuration.build_settings["PRODUCT_BUNDLE_IDENTIFIER"]}"
              puts "Signing Bundle Identifier : #{data["bundleIdentifier"]}"
              puts "Code Sign Identity : #{$code_sign_identity}"
              puts "Provisioning Profile : #{provisioning_plist['UUID']}"
              puts "Provisioning Profile Specifier: #{provisioning_plist['Name']}"
              puts "Development Team : #{$code_sign_development_team}"
              puts "Code Sign Style : Manual"

              puts "------------------------------------------------------"
          else
              puts "------------------------------------------------------"

              puts "Target Name : #{target.name}"
              puts "Target Build Configuration : #{configuration.name}"
              puts "Configuration Bundle Identifier : #{configuration.build_settings["PRODUCT_BUNDLE_IDENTIFIER"]}"
              puts "Signing Bundle Identifier : #{data["bundleIdentifier"]}"

              puts "------------------------------------------------------"
      		end
      	}
      }
    end

    xcproj.save

  rescue Exception => e
    abort_script(e)
  end
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
  unless $is_automatic_sign
    provisioning_profiles.each_with_index do |data, index|
      command_provisioning_plist = "security cms -D -i \"#{data}\" > \"#{$temporary_path}/_#{index}#{expOptProvisioningProfilePlist}\""
      run_command(command_provisioning_plist,false);

      provisioning_plist = Plist.parse_xml("#{$temporary_path}/_#{index}#{expOptProvisioningProfilePlist}")
      if index == 0
        application_profile_plist = provisioning_plist
      end
      provisioning_profile_object[bundle_identifiers[index]] = provisioning_plist['UUID']
    end
  end
  export_options['provisioningProfiles'] = provisioning_profile_object
  #####################


  if $is_automatic_sign
    export_options['signingStyle'] = :automatic
  else
    export_options['signingStyle'] = :manual
  end
  export_options['destination'] = :export
  
  if $is_sign_available
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
  end

  if $is_automatic_sign
    export_options['method'] = env_has_key("AC_AUTOSIGN_METHOD_FOR_EXPORT")
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
  if $is_automatic_sign
    key_path = env_has_key("AC_AUTOSIGN_CRED_PATH")
    key_id = env_has_key("AC_AUTOSIGN_KEY")
    issuer_id = env_has_key("AC_AUTOSIGN_ISSUER_ID")
    command_export = "xcodebuild -allowProvisioningUpdates -authenticationKeyPath #{key_path} -authenticationKeyID #{key_id} -authenticationKeyIssuerID #{issuer_id} -exportArchive -archivePath \"#$archive_path\" -exportPath \"#$output_path\" -exportOptionsPlist \"#{export_options}\""
  else
    command_export = "xcodebuild -exportArchive -archivePath \"#$archive_path\" -exportPath \"#$output_path\" -exportOptionsPlist \"#{export_options}\""
  end
  run_command_simple(command_export)

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
  if $is_automatic_sign
    key_path = env_has_key("AC_AUTOSIGN_CRED_PATH")
    key_id = env_has_key("AC_AUTOSIGN_KEY")
    issuer_id = env_has_key("AC_AUTOSIGN_ISSUER_ID")
    command = "xcodebuild -allowProvisioningUpdates -authenticationKeyPath #{key_path} -authenticationKeyID #{key_id} -authenticationKeyIssuerID #{issuer_id} -scheme \"#{$scheme}\" clean archive -archivePath \"#{$archive_path}\" -derivedDataPath \"#{$temporary_path}/DerivedData\" -destination \"generic/platform=iOS\""
  else
    command = "xcodebuild -scheme \"#{$scheme}\" clean archive -archivePath \"#{$archive_path}\" -derivedDataPath \"#{$temporary_path}/DerivedData\" -destination \"generic/platform=iOS\""
  end

  if $is_sign_available
    command.concat(" ")
    command.concat("CODE_SIGN_STYLE=Manual")
    command.concat(" ")
  elsif $is_automatic_sign
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

  run_command_simple(command)
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

      if File.directory?("#{product}/Watch")
        ids, profiles = get_bundle_identifiers_and_embedded_provisioning_profiles("#{product}/Watch")
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

def remove_folder(folder_path)
  begin
    FileUtils.rm_rf(folder_path)
    puts "Folder '#{folder_path}' has been successfully removed."
  rescue Errno::ENOENT
    puts "Folder '#{folder_path}' does not exist."
  rescue => e
    puts "An error occurred while removing the folder '#{folder_path}': #{e.message}"
  end
end

###############################################################

if $is_automatic_sign
  $certificate_properties = parse_certificate()
end

if $is_sign_available
  $signing_match_array = JSON.parse(File.read("#{ENV["AC_TEMP_DIR"]}/provisioningprofileandcertificates"))

  $signing_match_array.each { |signing_files| 
      $compatible_sign_files["#{signing_files["provisioningProfile"]}"] = "#{signing_files["cert"]}"
  }
  puts "Signing files: #{$compatible_sign_files}"

  $certificate_properties = parse_certificate()
  $bundle_identifiers_provisioning_profiles = parse_provisioning_profile()
  update_build_settings()
end

archive()
generate_archive_metadata()

if $is_sign_available or $is_automatic_sign
  export_options = generate_export_options()
  export_archive(export_options)
end

should_delete = ENV['AC_DELETE_ARCHIVE'] == 'true'
remove_folder($archive_path) if should_delete

###############################################################

### Write Environment Variable
open(ENV['AC_ENV_FILE_PATH'], 'a') { |f|
  f.puts "AC_ARCHIVE_METADATA_PATH=#{$metadata_path}"
  f.puts "AC_ARCHIVE_PATH=#{$archive_path}"
}

exit 0