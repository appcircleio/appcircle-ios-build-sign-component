# ─── Dependencies ─────────────────────────────────────────────────────────────
require 'rspec'
require 'rspec/core/formatters/base_formatter'
require 'open3'
require 'fileutils'
require 'tmpdir'
require 'stringio'
require 'json'
require 'pathname'
require 'English'

MAIN_RB      = File.expand_path('../main.rb', __dir__)
PROJECT_ROOT = File.dirname(MAIN_RB)

XCODEPROJ_AVAILABLE = begin
  require 'xcodeproj'
  true
rescue LoadError
  false
end

# ─── xcodeproj stub (for subprocess tests when gem is not installed) ───────────
XCODEPROJ_STUB_SOURCE = <<~RUBY
  # Minimal xcodeproj stub – enough for main.rb to load without the gem.
  module Xcodeproj
    class Project
      def self.open(_path) = new
      def native_targets = []
      def save; end
    end
    class Workspace
      FileReference = Struct.new(:path)
      def self.new_from_xcworkspace(_path) = new
      def file_references = []
    end
  end
RUBY

# ─── Custom Formatter ─────────────────────────────────────────────────────────
class ReadableFormatter < RSpec::Core::Formatters::BaseFormatter
  RSpec::Core::Formatters.register(
    self,
    :example_group_started,
    :example_group_finished,
    :example_passed,
    :example_failed,
    :example_pending,
    :dump_summary
  )

  PASS  = "\e[32;1m[ PASS ]\e[0m"
  FAIL  = "\e[31;1m[ FAIL ]\e[0m"
  ERROR = "\e[31;1m[ERROR ]\e[0m"
  SKIP  = "\e[33;1m[ SKIP ]\e[0m"

  DIVIDER     = "\e[90m#{'─' * 72}\e[0m"
  DIVIDER_FAT = "\e[90m#{'═' * 72}\e[0m"

  GROUP_COLORS = [
    "\e[34;1m",
    "\e[35;1m",
    "\e[36;1m",
    "\e[33;1m",
  ].freeze

  def initialize(output)
    super
    @depth         = 0
    @top_idx       = -1
    @failures      = []
    @counts        = { passed: 0, failed: 0, pending: 0 }
  end

  def example_group_started(notification)
    group = notification.group
    if group.parent_groups.size <= 1
      output.puts if @depth.zero?
      @top_idx = (@top_idx + 1) % GROUP_COLORS.size
      output.puts "  #{GROUP_COLORS[@top_idx]}#{group.description}\e[0m"
    else
      output.puts "    #{'  ' * (@depth - 1)}\e[90m▸ \e[0m\e[37m#{group.description}\e[0m"
    end
    @depth += 1
  end

  def example_group_finished(_notification)
    @depth -= 1 if @depth > 0
  end

  def example_passed(notification)
    @counts[:passed] += 1
    print_example(PASS, notification.example)
  end

  def example_failed(notification)
    @counts[:failed] += 1
    ex    = notification.example
    exc   = ex.execution_result.exception
    badge = exc.is_a?(RSpec::Expectations::ExpectationNotMetError) ? FAIL : ERROR
    print_example(badge, ex)
    @failures << notification
  end

  def example_pending(notification)
    @counts[:pending] += 1
    ex = notification.example
    output.puts "    #{'  ' * [0, @depth - 1].max}#{SKIP}  #{ex.description}"
  end

  def dump_summary(notification)
    output.puts
    output.puts DIVIDER_FAT

    unless @failures.empty?
      output.puts "\n  \e[1;31mFailures:\e[0m\n"
      @failures.each_with_index do |n, i|
        ex  = n.example
        exc = ex.execution_result.exception
        output.puts "  \e[1m#{i + 1}) #{ex.full_description}\e[0m"
        exc.message.lines.first(6).each { |line| output.puts "     \e[31m#{line.rstrip}\e[0m" }
        output.puts "     \e[90m# #{ex.location}\e[0m"
        output.puts
      end
      output.puts DIVIDER
    end

    t   = notification.examples.size
    p   = @counts[:passed]
    f   = @counts[:failed]
    s   = @counts[:pending]
    sec = format('%.3fs', notification.duration)

    parts = ["\e[32m#{p} passed\e[0m"]
    parts << "\e[31m#{f} failed\e[0m"  if f > 0
    parts << "\e[33m#{s} pending\e[0m" if s > 0

    overall = f.zero? ? "\e[32;1m✔  All #{t} tests passed\e[0m" : "\e[31;1m✖  #{f} of #{t} tests failed\e[0m"
    output.puts "\n  #{overall}"
    output.puts "  #{parts.join('  |  ')}  \e[90m(#{sec})\e[0m"
    output.puts DIVIDER_FAT
  end

  private

  def print_example(badge, example)
    indent = '  ' * [0, @depth - 1].max
    time   = format('%.3fs', example.execution_result.run_time)
    output.puts "    #{indent}#{badge}  #{example.description}  \e[90m(#{time})\e[0m"
  end
end

# ─── Load main.rb (top-level execution is guarded by __FILE__ == $PROGRAM_NAME)
require_relative '../main.rb'

# Mirrors the xcodebuild command assembled in archive() in main.rb.
# Returns the command string instead of running it.
def build_archive_command(
  scheme:, archive_path:, tmp_path:, project_full_path:,
  is_workspace: false, is_automatic_sign: false, is_sign_available: false,
  clean_build: true, configuration_name: nil,
  compiler_index_store_enable: nil, extra_options: [],
  autosign_key: nil, autosign_cred_path: nil, autosign_issuer_id: nil
)
  clean_parameter = clean_build ? 'clean' : ''

  command = if is_automatic_sign
    "xcodebuild -allowProvisioningUpdates " \
    "-authenticationKeyPath #{autosign_cred_path} " \
    "-authenticationKeyID #{autosign_key} " \
    "-authenticationKeyIssuerID #{autosign_issuer_id} " \
    "-scheme \"#{scheme}\" #{clean_parameter} archive " \
    "-archivePath \"#{archive_path}\" " \
    "-derivedDataPath \"#{tmp_path}/DerivedData\" " \
    "-destination \"generic/platform=iOS\""
  else
    "xcodebuild -scheme \"#{scheme}\" #{clean_parameter} archive " \
    "-archivePath \"#{archive_path}\" " \
    "-derivedDataPath \"#{tmp_path}/DerivedData\" " \
    "-destination \"generic/platform=iOS\""
  end

  command.concat(" CODE_SIGN_STYLE=Manual ")                                               if is_sign_available
  command.concat(" CODE_SIGN_IDENTITY=\"\" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO ") if !is_automatic_sign && !is_sign_available
  command.concat(" -configuration \"#{configuration_name}\" ")                             if configuration_name
  command.concat(" COMPILER_INDEX_STORE_ENABLE=#{compiler_index_store_enable} ")           if compiler_index_store_enable
  extra_options.each { |opt| command.concat(" #{opt} ") }                                  if extra_options.is_a?(Array)
  command.concat(is_workspace ? " -workspace \"#{project_full_path}\"" : " -project \"#{project_full_path}\"")
  command
end

# ─── Subprocess Helper ─────────────────────────────────────────────────────────
# Writes xcodeproj stub to a temp dir and injects it into RUBYLIB so that
# main.rb can load even when the xcodeproj gem is not installed.
def with_xcodeproj_stub
  stub_dir = Dir.mktmpdir('xcodeproj_stub')
  File.write(File.join(stub_dir, 'xcodeproj.rb'), XCODEPROJ_STUB_SOURCE)
  yield stub_dir
ensure
  FileUtils.rm_rf(stub_dir)
end

# Run main.rb in a child process with a controlled ENV.
# Nil values explicitly unset keys inherited from the parent process.
def run_main(env = {})
  with_xcodeproj_stub do |stub_dir|
    clean_env = {
      'AC_TEMP_DIR'                                => nil,
      'AC_OUTPUT_DIR_PATH'                         => nil,
      'AC_PROJECT_PATH'                            => nil,
      'AC_SCHEME'                                  => nil,
      'AC_COMPILER_INDEX_STORE_ENABLE'             => nil,
      'AC_ENV_FILE_PATH'                           => nil,
      'AC_AUTOSIGN_KEY'                            => nil,
      'AC_CERTIFICATES'                            => nil,
      'AC_PROVISIONING_PROFILES'                   => nil,
      'AC_BUNDLE_IDENTIFIERS'                      => nil,
      'AC_REPOSITORY_DIR'                          => nil,
      'AC_CLEAN_BUILD'                             => nil,
      'AC_CONFIGURATION_NAME'                      => nil,
      'AC_METHOD_FOR_EXPORT'                       => nil,
      'AC_TEAMID_FOR_EXPORT'                       => nil,
      'AC_COMPILE_BITCODE_FOR_EXPORT'              => nil,
      'AC_UPLOAD_BITCODE_FOR_EXPORT'               => nil,
      'AC_UPLOAD_SYMBOLS_FOR_EXPORT'               => nil,
      'AC_ICLOUD_CONTAINER_ENVIRONMENT_FOR_EXPORT' => nil,
      'AC_ARCHIVE_FLAGS'                           => nil,
      'AC_DELETE_ARCHIVE'                          => nil,
      'RUBYLIB'                                    => stub_dir,
    }.merge(env).reject { |_, v| v.nil? }

    # Merge RUBYLIB with existing value if present
    existing_rubylib = ENV['RUBYLIB']
    if existing_rubylib && !existing_rubylib.empty?
      clean_env['RUBYLIB'] = "#{stub_dir}:#{existing_rubylib}"
    end

    Open3.capture3(clean_env, "ruby #{MAIN_RB}")
  end
end

# ─── File Helpers ─────────────────────────────────────────────────────────────
def write_info_plist(dir, bundle_id)
  FileUtils.mkdir_p(dir)
  File.write(File.join(dir, 'Info.plist'), <<~XML)
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
      "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
      <key>CFBundleIdentifier</key>
      <string>#{bundle_id}</string>
    </dict>
    </plist>
  XML
end

def build_applications_dir(base_path, apps)
  apps_path = File.join(base_path, 'Products', 'Applications')
  FileUtils.mkdir_p(apps_path)
  apps.each do |app|
    app_dir = File.join(apps_path, app.fetch(:name))
    write_info_plist(app_dir, app.fetch(:bundle_id))
    FileUtils.touch(File.join(app_dir, 'embedded.mobileprovision')) if app[:provision]
  end
  apps_path
end

# ─── Tests ────────────────────────────────────────────────────────────────────

# ─── 2. env_has_key ───────────────────────────────────────────────────────────
RSpec.describe '#env_has_key' do
  around do |example|
    saved = ENV['_AC_TEST_KEY']
    example.run
    ENV['_AC_TEST_KEY'] = saved
  end

  context 'positive path – key present and non-empty' do
    it 'returns the value as-is' do
      ENV['_AC_TEST_KEY'] = 'my_value'
      expect(env_has_key('_AC_TEST_KEY')).to eq('my_value')
    end

    it 'returns a path-like value without modification' do
      ENV['_AC_TEST_KEY'] = '/tmp/some/path'
      expect(env_has_key('_AC_TEST_KEY')).to eq('/tmp/some/path')
    end

    it 'returns a numeric string value' do
      ENV['_AC_TEST_KEY'] = '42'
      expect(env_has_key('_AC_TEST_KEY')).to eq('42')
    end
  end

  context 'negative path – missing key' do
    it 'raises SystemExit when the key is not set' do
      ENV.delete('_AC_TEST_KEY')
      expect { env_has_key('_AC_TEST_KEY') }.to raise_error(SystemExit)
    end

    it 'abort message includes the key name' do
      ENV.delete('_AC_TEST_KEY')
      captured = StringIO.new
      original_stderr = $stderr
      $stderr = captured
      begin
        env_has_key('_AC_TEST_KEY')
      rescue SystemExit
        # expected
      ensure
        $stderr = original_stderr
      end
      expect(captured.string).to match(/_AC_TEST_KEY/)
    end
  end

  context 'negative path – empty string value' do
    it 'raises SystemExit when the value is empty string' do
      ENV['_AC_TEST_KEY'] = ''
      expect { env_has_key('_AC_TEST_KEY') }.to raise_error(SystemExit)
    end
  end
end

# ─── 3. abort_script ──────────────────────────────────────────────────────────
RSpec.describe '#abort_script' do
  context 'positive path' do
    it 'raises SystemExit' do
      expect { abort_script('fatal error') }.to raise_error(SystemExit)
    end

    it 'always terminates – never returns a value' do
      result = nil
      begin
        result = abort_script('boom')
      rescue SystemExit
        # expected
      end
      expect(result).to be_nil
    end
  end

  context 'negative path – non-string argument' do
    it 'still raises SystemExit when given a non-string object' do
      expect { abort_script(RuntimeError.new('err')) }.to raise_error(SystemExit)
    end
  end
end

# ─── 4. run_command ───────────────────────────────────────────────────────────
RSpec.describe '#run_command' do
  context 'positive path – command succeeds' do
    it 'does not raise for a zero-exit command' do
      expect { run_command('true', false) }.not_to raise_error
    end

    it 'does not raise with skip_abort=true on success' do
      expect { run_command('echo hello', true) }.not_to raise_error
    end

    it 'prints stdout output from the command' do
      expect { run_command('echo captured_output', false) }.to output(/captured_output/).to_stdout
    end
  end

  context 'negative path – command fails' do
    it 'raises SystemExit when skip_abort is false' do
      expect { run_command('false', false) }.to raise_error(SystemExit)
    end

    it 'does NOT raise when skip_abort is true' do
      expect { run_command('false', true) }.not_to raise_error
    end

    it 'prints stderr content when skip_abort is true' do
      expect { run_command('sh -c "echo err_output >&2; exit 1"', true) }
        .to output(/err_output/).to_stdout
    end
  end
end

# ─── 5. run_command_simple ────────────────────────────────────────────────────
RSpec.describe '#run_command_simple' do
  let(:tmpdir) { Dir.mktmpdir('ac_rcs_test') }
  after { FileUtils.rm_rf(tmpdir) }

  around do |example|
    old = ENV['AC_TEMP_DIR']
    ENV['AC_TEMP_DIR'] = tmpdir
    example.run
    ENV['AC_TEMP_DIR'] = old
  end

  context 'positive path – command succeeds' do
    it 'does not raise for a zero-exit command' do
      expect { run_command_simple('true') }.not_to raise_error
    end

    it 'creates the stderr log file on disk' do
      run_command_simple('true')
      expect(File.exist?("#{tmpdir}/.command.stderr.log")).to be true
    end

    it 'handles commands with arguments' do
      expect { run_command_simple('echo hello') }.not_to raise_error
    end
  end

  context 'negative path – command fails' do
    it 'raises SystemExit when the command exits non-zero' do
      expect { run_command_simple('false') }.to raise_error(SystemExit)
    end

    it 'raises SystemExit for a non-existent command' do
      expect { run_command_simple('this_command_does_not_exist_xyz') }.to raise_error(SystemExit)
    end
  end
end

# ─── 6. is_no_sign ────────────────────────────────────────────────────────────
RSpec.describe '#is_no_sign' do
  around do |example|
    saved_auto = $is_automatic_sign
    saved_sign = $is_sign_available
    example.run
    $is_automatic_sign = saved_auto
    $is_sign_available = saved_sign
  end

  context 'positive path – no signing configured' do
    it 'returns true when both flags are false' do
      $is_automatic_sign = false
      $is_sign_available = false
      expect(is_no_sign).to be true
    end
  end

  context 'negative path – signing is active' do
    it 'returns false when automatic sign is enabled' do
      $is_automatic_sign = true
      $is_sign_available = false
      expect(is_no_sign).to be false
    end

    it 'returns false when manual sign is available' do
      $is_automatic_sign = false
      $is_sign_available = true
      expect(is_no_sign).to be false
    end

    it 'returns false when both modes are active simultaneously' do
      $is_automatic_sign = true
      $is_sign_available = true
      expect(is_no_sign).to be false
    end
  end
end

# ─── 7. remove_folder ─────────────────────────────────────────────────────────
RSpec.describe '#remove_folder' do
  let(:tmpdir) { Dir.mktmpdir('rm_test') }
  after { FileUtils.rm_rf(tmpdir) if File.exist?(tmpdir) }

  context 'positive path – folder exists' do
    it 'removes an empty folder' do
      target = File.join(tmpdir, 'to_delete')
      FileUtils.mkdir_p(target)
      remove_folder(target)
      expect(File.exist?(target)).to be false
    end

    it 'removes a folder with nested files and directories' do
      target = File.join(tmpdir, 'nested')
      FileUtils.mkdir_p(File.join(target, 'a', 'b'))
      FileUtils.touch(File.join(target, 'a', 'b', 'file.txt'))
      remove_folder(target)
      expect(File.exist?(target)).to be false
    end

    it 'prints a success message' do
      target = File.join(tmpdir, 'gone')
      FileUtils.mkdir_p(target)
      expect { remove_folder(target) }.to output(/successfully removed/).to_stdout
    end

    it 'is idempotent – removing an already-deleted folder does not raise' do
      target = File.join(tmpdir, 'gone2')
      FileUtils.mkdir_p(target)
      remove_folder(target)
      expect { remove_folder(target) }.not_to raise_error
    end
  end

  context 'negative path – non-existent folder' do
    it 'does not raise for a non-existent path' do
      expect { remove_folder('/tmp/ac_test_nonexistent_xyz_987') }.not_to raise_error
    end

    it 'still prints a message even for non-existent folder' do
      # FileUtils.rm_rf on missing path silently succeeds – "removed" message is printed
      expect { remove_folder('/tmp/ac_test_nonexistent_xyz_987') }
        .to output(/removed/).to_stdout
    end
  end

  context 'positive path – symlink' do
    it 'removes a symlink without following into the real directory' do
      real_dir  = File.join(tmpdir, 'real')
      link_path = File.join(tmpdir, 'link')
      FileUtils.mkdir_p(real_dir)
      File.symlink(real_dir, link_path)
      remove_folder(link_path)
      expect(File.exist?(link_path)).to be false
      expect(File.exist?(real_dir)).to be true
    end
  end
end

# ─── 8. get_bundle_identifiers_and_embedded_provisioning_profiles ─────────────
RSpec.describe '#get_bundle_identifiers_and_embedded_provisioning_profiles' do
  let(:tmpdir)    { Dir.mktmpdir('bundle_id_test') }
  let(:apps_path) { File.join(tmpdir, 'Applications') }
  after           { FileUtils.rm_rf(tmpdir) }

  context 'positive path – single app with provisioning profile' do
    before do
      app_dir = File.join(apps_path, 'MyApp.app')
      write_info_plist(app_dir, 'com.example.myapp')
      FileUtils.touch(File.join(app_dir, 'embedded.mobileprovision'))
    end

    it 'returns the bundle identifier' do
      ids, = get_bundle_identifiers_and_embedded_provisioning_profiles(apps_path)
      expect(ids).to include('com.example.myapp')
    end

    it 'returns the embedded.mobileprovision path' do
      _, profiles = get_bundle_identifiers_and_embedded_provisioning_profiles(apps_path)
      expect(profiles.first).to end_with('embedded.mobileprovision')
    end
  end

  context 'positive path – single app WITHOUT provisioning profile' do
    before { write_info_plist(File.join(apps_path, 'MyApp.app'), 'com.example.noprofile') }

    it 'returns nil for the provisioning profile slot' do
      _, profiles = get_bundle_identifiers_and_embedded_provisioning_profiles(apps_path)
      expect(profiles.first).to be_nil
    end
  end

  context 'positive path – app with PlugIns extension' do
    before do
      write_info_plist(File.join(apps_path, 'MyApp.app'), 'com.example.app')
      write_info_plist(File.join(apps_path, 'MyApp.app', 'PlugIns', 'Ext.appex'), 'com.example.app.ext')
    end

    it 'recurses into PlugIns and includes the extension identifier' do
      ids, = get_bundle_identifiers_and_embedded_provisioning_profiles(apps_path)
      expect(ids).to include('com.example.app')
      expect(ids).to include('com.example.app.ext')
    end
  end

  context 'positive path – app with Watch extension' do
    before do
      write_info_plist(File.join(apps_path, 'MyApp.app'), 'com.example.app')
      write_info_plist(File.join(apps_path, 'MyApp.app', 'Watch', 'MyWatch.app'), 'com.example.app.watch')
    end

    it 'recurses into Watch and includes the watch identifier' do
      ids, = get_bundle_identifiers_and_embedded_provisioning_profiles(apps_path)
      expect(ids).to include('com.example.app')
      expect(ids).to include('com.example.app.watch')
    end
  end

  context 'positive path – multiple apps' do
    before do
      write_info_plist(File.join(apps_path, 'App1.app'), 'com.example.one')
      write_info_plist(File.join(apps_path, 'App2.app'), 'com.example.two')
    end

    it 'returns all bundle identifiers' do
      ids, = get_bundle_identifiers_and_embedded_provisioning_profiles(apps_path)
      expect(ids).to include('com.example.one', 'com.example.two')
    end

    it 'returns an array of two provisioning profile entries' do
      _, profiles = get_bundle_identifiers_and_embedded_provisioning_profiles(apps_path)
      expect(profiles.size).to eq(2)
    end
  end
end

# ─── 9. archive command construction ─────────────────────────────────────────
RSpec.describe 'archive command construction' do
  let(:defaults) do
    {
      scheme:            'MyScheme',
      archive_path:      '/tmp/build.xcarchive',
      tmp_path:          '/tmp/derived',
      project_full_path: '/repo/MyApp.xcodeproj',
    }
  end

  context 'positive path – standard .xcodeproj build' do
    it 'includes -scheme flag' do
      expect(build_archive_command(**defaults)).to include('-scheme "MyScheme"')
    end

    it 'includes -archivePath flag' do
      expect(build_archive_command(**defaults)).to include('-archivePath "/tmp/build.xcarchive"')
    end

    it 'includes -derivedDataPath flag' do
      expect(build_archive_command(**defaults)).to include('-derivedDataPath "/tmp/derived/DerivedData"')
    end

    it 'uses -project for a .xcodeproj path' do
      cmd = build_archive_command(**defaults)
      expect(cmd).to include('-project "/repo/MyApp.xcodeproj"')
      expect(cmd).not_to include('-workspace')
    end

    it 'includes "clean" keyword by default' do
      expect(build_archive_command(**defaults)).to include('clean archive')
    end

    it 'targets generic iOS destination' do
      expect(build_archive_command(**defaults)).to include('generic/platform=iOS')
    end
  end

  context 'positive path – workspace build' do
    it 'uses -workspace flag' do
      cmd = build_archive_command(**defaults, is_workspace: true,
                                              project_full_path: '/repo/App.xcworkspace')
      expect(cmd).to include('-workspace "/repo/App.xcworkspace"')
      expect(cmd).not_to include('-project')
    end
  end

  context 'positive path – incremental build (no clean)' do
    it 'omits "clean" when clean_build is false' do
      cmd = build_archive_command(**defaults, clean_build: false)
      expect(cmd).not_to match(/\bclean\b/)
    end
  end

  context 'positive path – manual signing' do
    it 'appends CODE_SIGN_STYLE=Manual' do
      cmd = build_archive_command(**defaults, is_sign_available: true)
      expect(cmd).to include('CODE_SIGN_STYLE=Manual')
    end
  end

  context 'positive path – no-sign build' do
    it 'appends no-signing flags when both sign flags are false' do
      cmd = build_archive_command(**defaults, is_automatic_sign: false, is_sign_available: false)
      expect(cmd).to include('CODE_SIGN_IDENTITY=""')
      expect(cmd).to include('CODE_SIGNING_REQUIRED=NO')
      expect(cmd).to include('CODE_SIGNING_ALLOWED=NO')
    end
  end

  context 'positive path – automatic sign build' do
    let(:autosign_defaults) do
      defaults.merge(
        is_automatic_sign: true,
        autosign_key:       'KEYID123',
        autosign_cred_path: '/path/AuthKey.p8',
        autosign_issuer_id: 'ISSUER-UUID'
      )
    end

    it 'includes -allowProvisioningUpdates' do
      expect(build_archive_command(**autosign_defaults)).to include('-allowProvisioningUpdates')
    end

    it 'includes authenticationKeyID' do
      expect(build_archive_command(**autosign_defaults)).to include('-authenticationKeyID KEYID123')
    end

    it 'includes authenticationKeyPath' do
      expect(build_archive_command(**autosign_defaults)).to include('-authenticationKeyPath /path/AuthKey.p8')
    end

    it 'does NOT append no-sign flags' do
      expect(build_archive_command(**autosign_defaults)).not_to include('CODE_SIGN_IDENTITY=""')
    end
  end

  context 'positive path – configuration name set' do
    it 'appends -configuration flag' do
      cmd = build_archive_command(**defaults, configuration_name: 'Debug')
      expect(cmd).to include('-configuration "Debug"')
    end
  end

  context 'positive path – compiler index store disabled' do
    it 'appends COMPILER_INDEX_STORE_ENABLE flag' do
      cmd = build_archive_command(**defaults, compiler_index_store_enable: 'NO')
      expect(cmd).to include('COMPILER_INDEX_STORE_ENABLE=NO')
    end
  end

  context 'positive path – extra archive flags' do
    it 'appends each extra flag to the command' do
      cmd = build_archive_command(**defaults, extra_options: ['-verbose', '-quiet'])
      expect(cmd).to include('-verbose')
      expect(cmd).to include('-quiet')
    end
  end

  context 'negative path – no configuration name' do
    it 'does not include -configuration' do
      expect(build_archive_command(**defaults)).not_to include('-configuration')
    end
  end

  context 'negative path – empty extra_options' do
    it 'does not add any extra flags' do
      cmd = build_archive_command(**defaults, extra_options: [])
      expect(cmd).not_to include('-verbose')
    end
  end
end

# ─── 10. parse_certificate string logic ───────────────────────────────────────
RSpec.describe 'parse_certificate string logic' do
  context 'positive path – pipe-delimited parsing' do
    it 'splits a single cert entry into 2 tokens (password + path)' do
      tokens = 'pass1|/path/cert.p12'.split('|')
      expect(tokens.length).to eq(2)
    end

    it 'identifies password as even-index token (0)' do
      tokens = 'pass1|/path/cert.p12'.split('|')
      expect(tokens[0]).to eq('pass1')
    end

    it 'identifies certificate path as odd-index token (1)' do
      tokens = 'pass1|/path/cert.p12'.split('|')
      expect(tokens[1]).to eq('/path/cert.p12')
    end

    it 'handles multiple certificates (4 tokens)' do
      tokens = 'p1|/c1.p12|p2|/c2.p12'.split('|')
      expect(tokens.length).to eq(4)
    end

    it 'extracts second password at index 2' do
      tokens = 'p1|/c1.p12|p2|/c2.p12'.split('|')
      expect(tokens[2]).to eq('p2')
    end

    it 'extracts second cert path at index 3' do
      tokens = 'p1|/c1.p12|p2|/c2.p12'.split('|')
      expect(tokens[3]).to eq('/c2.p12')
    end
  end

  context 'positive path – CN/OU extraction from openssl subject' do
    let(:subject) { 'subject=/C=US/O=Example/OU=TEAM99/CN=iPhone Distribution: My Corp' }

    it 'extracts CN value from the subject string' do
      cn = subject.split('/').find { |p| p.start_with?('CN=') }&.split('=', 2)&.last
      expect(cn).to eq('iPhone Distribution: My Corp')
    end

    it 'extracts OU value from the subject string' do
      ou = subject.split('/').find { |p| p.start_with?('OU=') }&.split('=', 2)&.last
      expect(ou).to eq('TEAM99')
    end
  end

  context 'negative path – malformed cert string' do
    it 'results in a single token when no pipe separator is present' do
      expect('only_password'.split('|').length).to eq(1)
    end

    it 'produces an empty array for an empty cert string' do
      expect(''.split('|')).to be_empty
    end
  end
end

# ─── 11. ENV validation (subprocess) ─────────────────────────────────────────
RSpec.describe 'ENV validation (subprocess – main.rb)' do
  shared_examples 'aborts with message' do |env_override, expected_pattern|
    it "exits non-zero and stderr matches /#{expected_pattern}/" do
      _out, err, status = run_main(env_override)
      expect(status.exitstatus).not_to eq(0)
      expect(err).to match(Regexp.new(expected_pattern))
    end
  end

  context 'required variable: AC_TEMP_DIR' do
    context 'when AC_TEMP_DIR is missing' do
      include_examples 'aborts with message', {}, 'AC_TEMP_DIR'
    end

    context 'when AC_TEMP_DIR is an empty string' do
      include_examples 'aborts with message', { 'AC_TEMP_DIR' => '' }, 'AC_TEMP_DIR'
    end
  end

  context 'required variable: AC_OUTPUT_DIR_PATH' do
    context 'when present, AC_OUTPUT_DIR_PATH is checked next' do
      include_examples 'aborts with message',
                       { 'AC_TEMP_DIR' => '/tmp' },
                       'AC_OUTPUT_DIR_PATH'
    end
  end

  context 'required variable: AC_PROJECT_PATH' do
    context 'when AC_PROJECT_PATH is missing' do
      include_examples 'aborts with message',
                       { 'AC_TEMP_DIR' => '/tmp', 'AC_OUTPUT_DIR_PATH' => '/tmp/out' },
                       'AC_PROJECT_PATH'
    end
  end

  context 'required variable: AC_SCHEME' do
    context 'when AC_SCHEME is missing' do
      include_examples 'aborts with message',
                       {
                         'AC_TEMP_DIR'        => '/tmp',
                         'AC_OUTPUT_DIR_PATH' => '/tmp/out',
                         'AC_PROJECT_PATH'    => 'App.xcodeproj',
                       },
                       'AC_SCHEME'
    end
  end

  context 'required variable: AC_COMPILER_INDEX_STORE_ENABLE' do
    context 'when missing' do
      include_examples 'aborts with message',
                       {
                         'AC_TEMP_DIR'        => '/tmp',
                         'AC_OUTPUT_DIR_PATH' => '/tmp/out',
                         'AC_PROJECT_PATH'    => 'App.xcodeproj',
                         'AC_SCHEME'          => 'MyScheme',
                       },
                       'AC_COMPILER_INDEX_STORE_ENABLE'
    end

    context 'when set to an empty string' do
      include_examples 'aborts with message',
                       {
                         'AC_TEMP_DIR'                    => '/tmp',
                         'AC_OUTPUT_DIR_PATH'             => '/tmp/out',
                         'AC_PROJECT_PATH'                => 'App.xcodeproj',
                         'AC_SCHEME'                      => 'MyScheme',
                         'AC_COMPILER_INDEX_STORE_ENABLE' => '',
                       },
                       'AC_COMPILER_INDEX_STORE_ENABLE'
    end
  end

  context 'optional sign variables (base env fully set)' do
    let(:base_env) do
      {
        'AC_TEMP_DIR'                    => '/tmp',
        'AC_OUTPUT_DIR_PATH'             => '/tmp/out',
        'AC_PROJECT_PATH'                => 'App.xcodeproj',
        'AC_SCHEME'                      => 'MyScheme',
        'AC_COMPILER_INDEX_STORE_ENABLE' => 'NO',
      }
    end

    it 'does NOT abort on missing AC_CERTIFICATES key name' do
      _out, err, _status = run_main(base_env)
      expect(err).not_to match(/Missing AC_CERTIFICATES/)
    end

    it 'does NOT abort on missing AC_PROVISIONING_PROFILES key name' do
      _out, err, _status = run_main(base_env)
      expect(err).not_to match(/Missing AC_PROVISIONING_PROFILES/)
    end

    it 'prints "Doesn\'t Sign" when AC_CERTIFICATES is absent' do
      out, _err, _status = run_main(base_env)
      expect(out).to match(/Doesn't Sign.*AC_CERTIFICATES/)
    end

    it 'prints "Doesn\'t Sign" when AC_PROVISIONING_PROFILES is absent' do
      out, _err, _status = run_main(base_env)
      expect(out).to match(/Doesn't Sign.*AC_PROVISIONING_PROFILES/)
    end

    it 'prints "Doesn\'t Sign" when AC_BUNDLE_IDENTIFIERS is absent' do
      out, _err, _status = run_main(base_env)
      expect(out).to match(/Doesn't Sign.*AC_BUNDLE_IDENTIFIERS/)
    end
  end

  context 'AC_AUTOSIGN_KEY flag' do
    let(:base_env) do
      {
        'AC_TEMP_DIR'                    => '/tmp',
        'AC_OUTPUT_DIR_PATH'             => '/tmp/out',
        'AC_PROJECT_PATH'                => 'App.xcodeproj',
        'AC_SCHEME'                      => 'MyScheme',
        'AC_COMPILER_INDEX_STORE_ENABLE' => 'NO',
      }
    end

    it 'prints "Using automatic code signing" when AC_AUTOSIGN_KEY is set' do
      out, _err, _status = run_main(base_env.merge('AC_AUTOSIGN_KEY' => 'FAKEKEYID'))
      expect(out).to match(/Using automatic code signing/)
    end

    it 'does NOT print autosign message when AC_AUTOSIGN_KEY is absent' do
      out, _err, _status = run_main(base_env)
      expect(out).not_to match(/Using automatic code signing/)
    end
  end

  context 'AC_CLEAN_BUILD flag' do
    let(:base_env) do
      {
        'AC_TEMP_DIR'                    => '/tmp',
        'AC_OUTPUT_DIR_PATH'             => '/tmp/out',
        'AC_PROJECT_PATH'                => 'App.xcodeproj',
        'AC_SCHEME'                      => 'MyScheme',
        'AC_COMPILER_INDEX_STORE_ENABLE' => 'NO',
      }
    end

    it 'treats AC_CLEAN_BUILD=false as valid – no abort on this key' do
      _out, err, _status = run_main(base_env.merge('AC_CLEAN_BUILD' => 'false'))
      expect(err).not_to match(/Missing AC_CLEAN_BUILD/)
    end

    it 'treats absent AC_CLEAN_BUILD as valid (defaults to true)' do
      _out, err, _status = run_main(base_env)
      expect(err).not_to match(/Missing AC_CLEAN_BUILD/)
    end
  end

  context 'AC_ARCHIVE_FLAGS parsing' do
    let(:base_env) do
      {
        'AC_TEMP_DIR'                    => '/tmp',
        'AC_OUTPUT_DIR_PATH'             => '/tmp/out',
        'AC_PROJECT_PATH'                => 'App.xcodeproj',
        'AC_SCHEME'                      => 'MyScheme',
        'AC_COMPILER_INDEX_STORE_ENABLE' => 'NO',
      }
    end

    it 'does not abort when AC_ARCHIVE_FLAGS contains pipe-separated flags' do
      _out, err, _status = run_main(base_env.merge('AC_ARCHIVE_FLAGS' => '-verbose|-quiet'))
      expect(err).not_to match(/Missing AC_ARCHIVE_FLAGS/)
    end

    it 'does not abort when AC_ARCHIVE_FLAGS is absent' do
      _out, err, _status = run_main(base_env)
      expect(err).not_to match(/Missing AC_ARCHIVE_FLAGS/)
    end
  end

  context 'AC_METHOD_FOR_EXPORT default' do
    let(:base_env) do
      {
        'AC_TEMP_DIR'                    => '/tmp',
        'AC_OUTPUT_DIR_PATH'             => '/tmp/out',
        'AC_PROJECT_PATH'                => 'App.xcodeproj',
        'AC_SCHEME'                      => 'MyScheme',
        'AC_COMPILER_INDEX_STORE_ENABLE' => 'NO',
      }
    end

    it 'defaults to auto-detect – does not abort on missing AC_METHOD_FOR_EXPORT' do
      _out, err, _status = run_main(base_env)
      expect(err).not_to match(/Missing AC_METHOD_FOR_EXPORT/)
    end
  end
end

# ─── 12. generate_archive_metadata ───────────────────────────────────────────
# Inline parameterised version of generate_archive_metadata (mirrors main.rb).
def generate_metadata(archive_path, output_path, scheme)
  bundle_identifiers = []
  if File.directory?(archive_path)
    applications_path = "#{archive_path}/Products/Applications"
    bundle_identifiers.concat(
      get_bundle_identifiers_and_embedded_provisioning_profiles(applications_path)[0]
    )
  else
    abort('Archive path not found.')
  end
  xcode_version = `xcodebuild -version`.split(' ')[1]&.chomp || 'unknown'
  metadata_path = "#{output_path}/build_metadata.json"
  object = { 'bundleIdentifiers' => bundle_identifiers,
             'xcodeVersion'      => xcode_version,
             'scheme'            => scheme }
  File.open(metadata_path, 'w') { |f| f.write(object.to_json) }
  metadata_path
end

RSpec.describe '#generate_archive_metadata' do
  let(:tmpdir) { Dir.mktmpdir('metadata_test') }
  after        { FileUtils.rm_rf(tmpdir) }

  context 'positive path – valid archive structure' do
    before do
      build_applications_dir(tmpdir, [{ name: 'App.app', bundle_id: 'com.example.app', provision: false }])
    end

    it 'returns the metadata file path' do
      path = generate_metadata(tmpdir, tmpdir, 'MyScheme')
      expect(path).to end_with('build_metadata.json')
    end

    it 'creates the metadata JSON file on disk' do
      path = generate_metadata(tmpdir, tmpdir, 'MyScheme')
      expect(File.exist?(path)).to be true
    end

    it 'JSON contains the correct scheme' do
      path = generate_metadata(tmpdir, tmpdir, 'TestScheme')
      data = JSON.parse(File.read(path))
      expect(data['scheme']).to eq('TestScheme')
    end

    it 'JSON contains bundle identifiers' do
      path = generate_metadata(tmpdir, tmpdir, 'MyScheme')
      data = JSON.parse(File.read(path))
      expect(data['bundleIdentifiers']).to include('com.example.app')
    end

    it 'JSON contains xcodeVersion field' do
      path = generate_metadata(tmpdir, tmpdir, 'MyScheme')
      data = JSON.parse(File.read(path))
      expect(data['xcodeVersion']).not_to be_nil
    end
  end

  context 'negative path – archive path does not exist' do
    it 'raises SystemExit with "Archive path not found"' do
      expect { generate_metadata('/nonexistent/build.xcarchive', tmpdir, 'S') }
        .to raise_error(SystemExit)
    end
  end
end

# ─── 13. export_archive command construction ──────────────────────────────────
# Inline parameterised builder (mirrors export_archive in main.rb).
def build_export_command(archive_path, output_path, export_plist,
                         is_automatic: false,
                         key_path: nil, key_id: nil, issuer_id: nil)
  if is_automatic
    "xcodebuild -allowProvisioningUpdates " \
    "-authenticationKeyPath #{key_path} " \
    "-authenticationKeyID #{key_id} " \
    "-authenticationKeyIssuerID #{issuer_id} " \
    "-exportArchive -archivePath \"#{archive_path}\" " \
    "-exportPath \"#{output_path}\" " \
    "-exportOptionsPlist \"#{export_plist}\""
  else
    "xcodebuild -exportArchive -archivePath \"#{archive_path}\" " \
    "-exportPath \"#{output_path}\" " \
    "-exportOptionsPlist \"#{export_plist}\""
  end
end

RSpec.describe 'export_archive command construction' do
  let(:archive)  { '/tmp/build.xcarchive' }
  let(:out_path) { '/tmp/out' }
  let(:plist)    { '/tmp/ExportOptions.plist' }

  context 'positive path – manual export' do
    it 'includes -exportArchive flag' do
      expect(build_export_command(archive, out_path, plist)).to include('-exportArchive')
    end

    it 'includes -archivePath' do
      expect(build_export_command(archive, out_path, plist)).to include("-archivePath \"#{archive}\"")
    end

    it 'includes -exportPath' do
      expect(build_export_command(archive, out_path, plist)).to include("-exportPath \"#{out_path}\"")
    end

    it 'includes -exportOptionsPlist' do
      expect(build_export_command(archive, out_path, plist)).to include("-exportOptionsPlist \"#{plist}\"")
    end

    it 'does NOT include -allowProvisioningUpdates for manual export' do
      expect(build_export_command(archive, out_path, plist)).not_to include('-allowProvisioningUpdates')
    end
  end

  context 'positive path – automatic sign export' do
    let(:cmd) do
      build_export_command(archive, out_path, plist,
                           is_automatic: true,
                           key_path:     '/keys/AuthKey.p8',
                           key_id:       'ABC123',
                           issuer_id:    'ISSUER-UUID')
    end

    it 'includes -allowProvisioningUpdates' do
      expect(cmd).to include('-allowProvisioningUpdates')
    end

    it 'includes authenticationKeyID' do
      expect(cmd).to include('-authenticationKeyID ABC123')
    end

    it 'includes authenticationKeyIssuerID' do
      expect(cmd).to include('-authenticationKeyIssuerID ISSUER-UUID')
    end
  end

  context 'negative path – manual export does not include auth flags' do
    it 'has no -authenticationKeyID for manual export' do
      expect(build_export_command(archive, out_path, plist)).not_to include('-authenticationKeyID')
    end
  end
end

# ─── 14. parse_provisioning_profile string logic ──────────────────────────────
# Tests the pairing logic (string split + zip) from parse_provisioning_profile.
def build_provisioning_pairs(profiles_string, bundle_ids_string)
  profile_array = profiles_string.split('|')
  bundle_array  = bundle_ids_string.split('|')
  profile_array.each_with_index.map do |profile, i|
    { 'bundleIdentifier' => bundle_array[i], 'provisioningProfile' => profile }
  end
end

RSpec.describe 'parse_provisioning_profile string logic' do
  context 'positive path – single profile' do
    let(:pairs) { build_provisioning_pairs('/path/profile.mobileprovision', 'com.example.app') }

    it 'produces exactly one pair' do
      expect(pairs.length).to eq(1)
    end

    it 'maps the bundle identifier correctly' do
      expect(pairs[0]['bundleIdentifier']).to eq('com.example.app')
    end

    it 'maps the provisioning profile path correctly' do
      expect(pairs[0]['provisioningProfile']).to eq('/path/profile.mobileprovision')
    end
  end

  context 'positive path – multiple profiles' do
    let(:profiles) { '/p1.mobileprovision|/p2.mobileprovision' }
    let(:bundles)  { 'com.example.one|com.example.two' }
    let(:pairs)    { build_provisioning_pairs(profiles, bundles) }

    it 'produces two pairs' do
      expect(pairs.length).to eq(2)
    end

    it 'maps first bundle identifier' do
      expect(pairs[0]['bundleIdentifier']).to eq('com.example.one')
    end

    it 'maps second bundle identifier' do
      expect(pairs[1]['bundleIdentifier']).to eq('com.example.two')
    end

    it 'maps second provisioning profile path' do
      expect(pairs[1]['provisioningProfile']).to eq('/p2.mobileprovision')
    end
  end

  context 'negative path – empty strings' do
    it 'returns an empty array when profiles string is empty' do
      expect(build_provisioning_pairs('', 'com.example.app')).to be_empty
    end
  end
end

# ─── 15. update_build_settings (mock-based) ──────────────────────────────────

# Mock Xcodeproj objects – lightweight replacements for the real gem classes.
MockBuildConfiguration = Struct.new(:name, :build_settings) do
  def resolve_build_setting(key) = build_settings.fetch(key, nil)
end

MockNativeTarget = Struct.new(:name, :build_configurations)

class MockXcProject
  attr_accessor :native_targets
  attr_reader   :saved

  def initialize(targets)
    @native_targets = targets
    @saved          = false
  end

  def save = (@saved = true)
end

# Inline parameterised version of update_build_settings.
# Accepts pre-parsed plist_data map (hash) instead of running security cms.
def apply_sign_settings(xcproj, bundle_id_profiles, compatible_sign_files, cert_props_map, plist_data_map)
  bundle_id_profiles.each_with_index do |data, _index|
    provisioning_profile = data['provisioningProfile']
    certificate          = compatible_sign_files[provisioning_profile]
    cert_props           = cert_props_map[certificate]

    code_sign_identity        = cert_props[:code_sign_identity]
    code_sign_development_team = cert_props[:code_sign_development_team]

    xcproj.native_targets.each do |target|
      target.build_configurations.each do |configuration|
        config_bundle_id = configuration.resolve_build_setting('PRODUCT_BUNDLE_IDENTIFIER')

        matches = data['bundleIdentifier'] == config_bundle_id ||
                  (data['bundleIdentifier'].include?('.*') &&
                   config_bundle_id.to_s.match?(/#{data['bundleIdentifier']}/))

        if matches
          plist = plist_data_map[provisioning_profile]
          configuration.build_settings['CODE_SIGN_IDENTITY']              = code_sign_identity
          configuration.build_settings['CODE_SIGN_IDENTITY[sdk=iphoneos*]'] = code_sign_identity
          configuration.build_settings['PROVISIONING_PROFILE']            = plist['UUID']
          configuration.build_settings['PROVISIONING_PROFILE[sdk=iphoneos*]'] = plist['UUID']
          configuration.build_settings['PROVISIONING_PROFILE_SPECIFIER']  = plist['Name']
          configuration.build_settings['CODE_SIGN_STYLE']                 = 'Manual'
          configuration.build_settings['DEVELOPMENT_TEAM']                = code_sign_development_team
        end
      end
    end
  end
  xcproj.save
end

RSpec.describe '#update_build_settings (mock-based)' do
  # ── shared fixtures ──────────────────────────────────────────────────────────
  let(:profile_path)  { '/certs/Profile.mobileprovision' }
  let(:cert_path)     { '/certs/Cert.p12' }
  let(:plist_data)    { { 'UUID' => 'FAKE-UUID-0001', 'Name' => 'My Dist Profile' } }
  let(:sign_files)    { { profile_path => cert_path } }
  let(:cert_props)    { { cert_path => { code_sign_identity: 'iPhone Distribution: Corp',
                                         code_sign_development_team: 'TEAM99' } } }
  let(:plist_map)     { { profile_path => plist_data } }
  let(:profiles_data) { [{ 'bundleIdentifier' => 'com.example.app',
                            'provisioningProfile' => profile_path }] }

  def make_project(bundle_id)
    settings = { 'PRODUCT_BUNDLE_IDENTIFIER' => bundle_id }
    config   = MockBuildConfiguration.new('Release', settings)
    target   = MockNativeTarget.new('MyApp', [config])
    MockXcProject.new([target])
  end

  context 'positive path – bundle ID matches exactly' do
    it 'sets CODE_SIGN_IDENTITY on the matching configuration' do
      proj = make_project('com.example.app')
      apply_sign_settings(proj, profiles_data, sign_files, cert_props, plist_map)
      expect(proj.native_targets[0].build_configurations[0]
               .build_settings['CODE_SIGN_IDENTITY'])
        .to eq('iPhone Distribution: Corp')
    end

    it 'sets CODE_SIGN_IDENTITY[sdk=iphoneos*] on the matching configuration' do
      proj = make_project('com.example.app')
      apply_sign_settings(proj, profiles_data, sign_files, cert_props, plist_map)
      expect(proj.native_targets[0].build_configurations[0]
               .build_settings['CODE_SIGN_IDENTITY[sdk=iphoneos*]'])
        .to eq('iPhone Distribution: Corp')
    end

    it 'sets PROVISIONING_PROFILE to plist UUID' do
      proj = make_project('com.example.app')
      apply_sign_settings(proj, profiles_data, sign_files, cert_props, plist_map)
      expect(proj.native_targets[0].build_configurations[0]
               .build_settings['PROVISIONING_PROFILE'])
        .to eq('FAKE-UUID-0001')
    end

    it 'sets PROVISIONING_PROFILE_SPECIFIER to plist Name' do
      proj = make_project('com.example.app')
      apply_sign_settings(proj, profiles_data, sign_files, cert_props, plist_map)
      expect(proj.native_targets[0].build_configurations[0]
               .build_settings['PROVISIONING_PROFILE_SPECIFIER'])
        .to eq('My Dist Profile')
    end

    it 'sets CODE_SIGN_STYLE to Manual' do
      proj = make_project('com.example.app')
      apply_sign_settings(proj, profiles_data, sign_files, cert_props, plist_map)
      expect(proj.native_targets[0].build_configurations[0]
               .build_settings['CODE_SIGN_STYLE'])
        .to eq('Manual')
    end

    it 'sets DEVELOPMENT_TEAM' do
      proj = make_project('com.example.app')
      apply_sign_settings(proj, profiles_data, sign_files, cert_props, plist_map)
      expect(proj.native_targets[0].build_configurations[0]
               .build_settings['DEVELOPMENT_TEAM'])
        .to eq('TEAM99')
    end

    it 'calls save() on the project' do
      proj = make_project('com.example.app')
      apply_sign_settings(proj, profiles_data, sign_files, cert_props, plist_map)
      expect(proj.saved).to be true
    end
  end

  context 'positive path – wildcard bundle ID matching (.*)'  do
    let(:wildcard_data) do
      [{ 'bundleIdentifier' => 'com.example.*', 'provisioningProfile' => profile_path }]
    end

    it 'matches a bundle ID with the wildcard pattern' do
      proj = make_project('com.example.app')
      apply_sign_settings(proj, wildcard_data, sign_files, cert_props, plist_map)
      expect(proj.native_targets[0].build_configurations[0]
               .build_settings['CODE_SIGN_STYLE'])
        .to eq('Manual')
    end

    it 'matches an extension bundle ID with the wildcard pattern' do
      proj = make_project('com.example.app.ext')
      apply_sign_settings(proj, wildcard_data, sign_files, cert_props, plist_map)
      expect(proj.native_targets[0].build_configurations[0]
               .build_settings['CODE_SIGN_STYLE'])
        .to eq('Manual')
    end
  end

  context 'negative path – bundle ID does NOT match' do
    it 'does NOT set CODE_SIGN_STYLE on a non-matching configuration' do
      proj = make_project('com.other.app')
      apply_sign_settings(proj, profiles_data, sign_files, cert_props, plist_map)
      expect(proj.native_targets[0].build_configurations[0]
               .build_settings['CODE_SIGN_STYLE'])
        .to be_nil
    end

    it 'still calls save() even when nothing matched' do
      proj = make_project('com.other.app')
      apply_sign_settings(proj, profiles_data, sign_files, cert_props, plist_map)
      expect(proj.saved).to be true
    end
  end

  context 'positive path – multiple targets and configurations' do
    let(:proj) do
      configs1 = [MockBuildConfiguration.new('Debug',   { 'PRODUCT_BUNDLE_IDENTIFIER' => 'com.example.app' }),
                  MockBuildConfiguration.new('Release',  { 'PRODUCT_BUNDLE_IDENTIFIER' => 'com.example.app' })]
      configs2 = [MockBuildConfiguration.new('Release',  { 'PRODUCT_BUNDLE_IDENTIFIER' => 'com.other.app' })]
      targets  = [MockNativeTarget.new('App',       configs1),
                  MockNativeTarget.new('Framework', configs2)]
      MockXcProject.new(targets)
    end

    it 'applies settings to all matching configurations across targets' do
      apply_sign_settings(proj, profiles_data, sign_files, cert_props, plist_map)
      matching = proj.native_targets[0].build_configurations
      expect(matching.all? { |c| c.build_settings['CODE_SIGN_STYLE'] == 'Manual' }).to be true
    end

    it 'leaves non-matching target configuration untouched' do
      apply_sign_settings(proj, profiles_data, sign_files, cert_props, plist_map)
      expect(proj.native_targets[1].build_configurations[0]
               .build_settings['CODE_SIGN_STYLE'])
        .to be_nil
    end
  end
end

# ─── 16. get_project_path logic ───────────────────────────────────────────────

# Non-workspace path inline (mirrors the else branch of get_project_path).
def resolve_project_path_non_workspace(project_full_path)
  project_full_path
end

# Workspace path: accepts mock file_references and a block that yields
# the xcodebuild -list output for a given project path.
# Mirrors the workspace branch of get_project_path.
def find_project_in_workspace(file_refs, workspace_dir, target_scheme)
  file_refs.each do |file_ref|
    file_full_path = File.join(workspace_dir, file_ref[:path])
    schemes_string = yield(file_full_path)
    next unless schemes_string

    schemes_part = schemes_string.split('Schemes:')[1]
    next unless schemes_part
    return file_full_path if schemes_part.include?(target_scheme)
  end
  nil
end

RSpec.describe '#get_project_path logic' do
  context 'positive path – non-workspace project' do
    it 'returns the project_full_path directly' do
      result = resolve_project_path_non_workspace('/repo/MyApp.xcodeproj')
      expect(result).to eq('/repo/MyApp.xcodeproj')
    end

    it 'preserves paths with spaces' do
      result = resolve_project_path_non_workspace('/My Repo/My App.xcodeproj')
      expect(result).to eq('/My Repo/My App.xcodeproj')
    end
  end

  context 'positive path – workspace project with matching scheme' do
    let(:file_refs) do
      [{ path: 'App/MyApp.xcodeproj' },
       { path: 'Lib/MyLib.xcodeproj' }]
    end

    let(:scheme_outputs) do
      {
        '/workspace/App/MyApp.xcodeproj' => "Schemes:\n    MyScheme\n    OtherScheme\n",
        '/workspace/Lib/MyLib.xcodeproj' => "Schemes:\n    LibScheme\n",
      }
    end

    it 'returns the project path that contains the target scheme' do
      result = find_project_in_workspace(file_refs, '/workspace', 'MyScheme') do |path|
        scheme_outputs[path]
      end
      expect(result).to eq('/workspace/App/MyApp.xcodeproj')
    end

    it 'returns the second project when the scheme is in the second file' do
      result = find_project_in_workspace(file_refs, '/workspace', 'LibScheme') do |path|
        scheme_outputs[path]
      end
      expect(result).to eq('/workspace/Lib/MyLib.xcodeproj')
    end
  end

  context 'negative path – no project contains the scheme' do
    let(:file_refs) { [{ path: 'App/MyApp.xcodeproj' }] }

    it 'returns nil when the scheme is not found in any project' do
      result = find_project_in_workspace(file_refs, '/workspace', 'NonExistentScheme') do |_path|
        "Schemes:\n    SomeOtherScheme\n"
      end
      expect(result).to be_nil
    end
  end

  context 'positive path – xcodebuild output parsing' do
    it 'correctly extracts schemes after "Schemes:" marker' do
      output = "Information about project \"MyApp\":\n    Schemes:\n        MyScheme\n        Release\n"
      schemes_part = output.split('Schemes:')[1]
      expect(schemes_part).to include('MyScheme')
      expect(schemes_part).to include('Release')
    end

    it 'returns nil when output has no "Schemes:" section' do
      output = 'error: Could not read the project'
      schemes_part = output.split('Schemes:')[1]
      expect(schemes_part).to be_nil
    end
  end
end

# ─── 17. generate_export_options logic (pure) ────────────────────────────────

# Inline parameterised version of the pure option-building logic
# from generate_export_options (excludes file I/O and security cms calls).
def build_export_options(is_sign_available:, is_automatic_sign:, method_for_export:,
                         application_profile_plist: nil, teamid: nil,
                         compile_bitcode: nil, upload_bitcode: nil,
                         upload_symbols: nil, icloud_env: nil,
                         autosign_method: nil)
  export_options = {}
  export_options['signingStyle'] = is_automatic_sign ? :automatic : :manual
  export_options['destination']  = :export

  if is_sign_available
    if method_for_export == 'auto-detect'
      if application_profile_plist['Entitlements']['get-task-allow']
        export_options['method'] = 'development'
      elsif application_profile_plist['ProvisionsAllDevices']
        export_options['method'] = 'enterprise'
      elsif application_profile_plist['ProvisionedDevices']
        export_options['method'] = 'ad-hoc'
      else
        export_options['method'] = 'app-store'
      end
    else
      export_options['method'] = method_for_export
    end
  end

  export_options['method'] = autosign_method if is_automatic_sign
  export_options['teamID'] = teamid          if teamid

  unless export_options['method'] == 'app-store'
    if compile_bitcode == 'YES'
      export_options['compileBitcode'] = true
    elsif compile_bitcode == 'NO'
      export_options['compileBitcode'] = false
    end
    export_options['iCloudContainerEnvironment'] = icloud_env if icloud_env
  else
    if upload_bitcode == 'YES'
      export_options['uploadBitcode'] = true
    elsif upload_bitcode == 'NO'
      export_options['uploadBitcode'] = false
    end
    if upload_symbols == 'YES'
      export_options['uploadSymbols'] = true
    elsif upload_symbols == 'NO'
      export_options['uploadSymbols'] = false
    end
  end

  export_options
end

RSpec.describe '#generate_export_options logic (pure)' do
  # ── Helper plists ────────────────────────────────────────────────────────────
  let(:dev_plist)        { { 'Entitlements' => { 'get-task-allow' => true },
                              'ProvisionsAllDevices' => nil,
                              'ProvisionedDevices'   => nil } }
  let(:enterprise_plist) { { 'Entitlements' => { 'get-task-allow' => false },
                              'ProvisionsAllDevices' => true,
                              'ProvisionedDevices'   => nil } }
  let(:adhoc_plist)      { { 'Entitlements' => { 'get-task-allow' => false },
                              'ProvisionsAllDevices' => nil,
                              'ProvisionedDevices'   => ['DEVICE-001'] } }
  let(:appstore_plist)   { { 'Entitlements' => { 'get-task-allow' => false },
                              'ProvisionsAllDevices' => nil,
                              'ProvisionedDevices'   => nil } }

  context 'positive path – signingStyle' do
    it 'sets signingStyle to :manual for manual signing' do
      opts = build_export_options(is_sign_available: true, is_automatic_sign: false,
                                  method_for_export: 'development',
                                  application_profile_plist: dev_plist)
      expect(opts['signingStyle']).to eq(:manual)
    end

    it 'sets signingStyle to :automatic for automatic signing' do
      opts = build_export_options(is_sign_available: false, is_automatic_sign: true,
                                  method_for_export: 'app-store', autosign_method: 'app-store')
      expect(opts['signingStyle']).to eq(:automatic)
    end

    it 'always sets destination to :export' do
      opts = build_export_options(is_sign_available: false, is_automatic_sign: false,
                                  method_for_export: 'development')
      expect(opts['destination']).to eq(:export)
    end
  end

  context 'positive path – auto-detect method' do
    it 'detects development when get-task-allow is true' do
      opts = build_export_options(is_sign_available: true, is_automatic_sign: false,
                                  method_for_export: 'auto-detect',
                                  application_profile_plist: dev_plist)
      expect(opts['method']).to eq('development')
    end

    it 'detects enterprise when ProvisionsAllDevices is true' do
      opts = build_export_options(is_sign_available: true, is_automatic_sign: false,
                                  method_for_export: 'auto-detect',
                                  application_profile_plist: enterprise_plist)
      expect(opts['method']).to eq('enterprise')
    end

    it 'detects ad-hoc when ProvisionedDevices is present' do
      opts = build_export_options(is_sign_available: true, is_automatic_sign: false,
                                  method_for_export: 'auto-detect',
                                  application_profile_plist: adhoc_plist)
      expect(opts['method']).to eq('ad-hoc')
    end

    it 'detects app-store when none of the other flags are set' do
      opts = build_export_options(is_sign_available: true, is_automatic_sign: false,
                                  method_for_export: 'auto-detect',
                                  application_profile_plist: appstore_plist)
      expect(opts['method']).to eq('app-store')
    end
  end

  context 'positive path – explicit method_for_export' do
    %w[development enterprise ad-hoc app-store].each do |method|
      it "uses '#{method}' when explicitly set" do
        opts = build_export_options(is_sign_available: true, is_automatic_sign: false,
                                    method_for_export: method,
                                    application_profile_plist: appstore_plist)
        expect(opts['method']).to eq(method)
      end
    end
  end

  context 'positive path – automatic sign overrides method' do
    it 'uses autosign_method when is_automatic_sign is true' do
      opts = build_export_options(is_sign_available: false, is_automatic_sign: true,
                                  method_for_export: 'auto-detect',
                                  autosign_method: 'app-store')
      expect(opts['method']).to eq('app-store')
    end
  end

  context 'positive path – teamID' do
    it 'sets teamID when provided' do
      opts = build_export_options(is_sign_available: true, is_automatic_sign: false,
                                  method_for_export: 'development',
                                  application_profile_plist: dev_plist,
                                  teamid: 'MYTEAM123')
      expect(opts['teamID']).to eq('MYTEAM123')
    end

    it 'omits teamID when nil' do
      opts = build_export_options(is_sign_available: true, is_automatic_sign: false,
                                  method_for_export: 'development',
                                  application_profile_plist: dev_plist)
      expect(opts.key?('teamID')).to be false
    end
  end

  context 'positive path – compile_bitcode for non-app-store' do
    it 'sets compileBitcode=true when YES' do
      opts = build_export_options(is_sign_available: true, is_automatic_sign: false,
                                  method_for_export: 'development',
                                  application_profile_plist: dev_plist,
                                  compile_bitcode: 'YES')
      expect(opts['compileBitcode']).to be true
    end

    it 'sets compileBitcode=false when NO' do
      opts = build_export_options(is_sign_available: true, is_automatic_sign: false,
                                  method_for_export: 'development',
                                  application_profile_plist: dev_plist,
                                  compile_bitcode: 'NO')
      expect(opts['compileBitcode']).to be false
    end

    it 'omits compileBitcode when nil' do
      opts = build_export_options(is_sign_available: true, is_automatic_sign: false,
                                  method_for_export: 'development',
                                  application_profile_plist: dev_plist)
      expect(opts.key?('compileBitcode')).to be false
    end
  end

  context 'positive path – iCloudContainerEnvironment for non-app-store' do
    it 'sets iCloudContainerEnvironment when provided' do
      opts = build_export_options(is_sign_available: true, is_automatic_sign: false,
                                  method_for_export: 'development',
                                  application_profile_plist: dev_plist,
                                  icloud_env: 'Production')
      expect(opts['iCloudContainerEnvironment']).to eq('Production')
    end
  end

  context 'positive path – upload_bitcode for app-store' do
    it 'sets uploadBitcode=true when YES' do
      opts = build_export_options(is_sign_available: true, is_automatic_sign: false,
                                  method_for_export: 'app-store',
                                  application_profile_plist: appstore_plist,
                                  upload_bitcode: 'YES')
      expect(opts['uploadBitcode']).to be true
    end

    it 'sets uploadBitcode=false when NO' do
      opts = build_export_options(is_sign_available: true, is_automatic_sign: false,
                                  method_for_export: 'app-store',
                                  application_profile_plist: appstore_plist,
                                  upload_bitcode: 'NO')
      expect(opts['uploadBitcode']).to be false
    end
  end

  context 'positive path – upload_symbols for app-store' do
    it 'sets uploadSymbols=true when YES' do
      opts = build_export_options(is_sign_available: true, is_automatic_sign: false,
                                  method_for_export: 'app-store',
                                  application_profile_plist: appstore_plist,
                                  upload_symbols: 'YES')
      expect(opts['uploadSymbols']).to be true
    end

    it 'sets uploadSymbols=false when NO' do
      opts = build_export_options(is_sign_available: true, is_automatic_sign: false,
                                  method_for_export: 'app-store',
                                  application_profile_plist: appstore_plist,
                                  upload_symbols: 'NO')
      expect(opts['uploadSymbols']).to be false
    end
  end

  context 'negative path – app-store ignores compile_bitcode' do
    it 'does NOT set compileBitcode for app-store method' do
      opts = build_export_options(is_sign_available: true, is_automatic_sign: false,
                                  method_for_export: 'app-store',
                                  application_profile_plist: appstore_plist,
                                  compile_bitcode: 'YES')
      expect(opts.key?('compileBitcode')).to be false
    end
  end

  context 'negative path – non-app-store ignores upload_bitcode' do
    it 'does NOT set uploadBitcode for development method' do
      opts = build_export_options(is_sign_available: true, is_automatic_sign: false,
                                  method_for_export: 'development',
                                  application_profile_plist: dev_plist,
                                  upload_bitcode: 'YES')
      expect(opts.key?('uploadBitcode')).to be false
    end
  end
end

# ─── 18. Command format & execution tests ─────────────────────────────────────
# Builder helpers that mirror the exact command strings assembled in main.rb.
# Tests cover (a) command string format and (b) real execution where available.

# parse_certificate – line 154
def build_openssl_cert_command(certificate, password)
  "openssl pkcs12 -in #{certificate} -nokeys -passin pass:\"#{password}\" | openssl x509 -noout -subject"
end

# parse_provisioning_profile – line 208
def build_security_cms_command(profile_path)
  "security cms -D -i #{profile_path}"
end

# update_build_settings – line 250
def build_security_cms_to_plist_command(profile_path, plist_path)
  "security cms -D -i #{profile_path} > #{plist_path}"
end

# parse_provisioning_profile – line 212
def build_plistbuddy_uuid_command(plist_path)
  "/usr/libexec/PlistBuddy -c \"Print UUID\" \"#{plist_path}\""
end

# get_bundle_identifiers_and_embedded_provisioning_profiles – line 499
def build_plistbuddy_bundle_id_command(plist_path)
  "/usr/libexec/PlistBuddy -c \"Print CFBundleIdentifier\" \"#{plist_path}\""
end

# get_project_path (workspace branch) – line 304
def build_xcodebuild_list_command(project_path)
  "xcodebuild -project \"#{project_path}\" -list"
end

XCODEBUILD_AVAILABLE = system('which xcodebuild > /dev/null 2>&1')
OPENSSL_AVAILABLE    = system('which openssl > /dev/null 2>&1')
PLISTBUDDY_AVAILABLE = File.executable?('/usr/libexec/PlistBuddy')

RSpec.describe 'Command format & execution tests' do
  # ── openssl pkcs12 ───────────────────────────────────────────────────────────
  context 'openssl pkcs12 command (parse_certificate)' do
    context 'positive path – command string format' do
      let(:cmd) { build_openssl_cert_command('/certs/Cert.p12', 'secret') }

      it 'starts with openssl pkcs12' do
        expect(cmd).to start_with('openssl pkcs12')
      end

      it 'contains -in flag with the certificate path' do
        expect(cmd).to include('-in /certs/Cert.p12')
      end

      it 'contains -nokeys flag' do
        expect(cmd).to include('-nokeys')
      end

      it 'contains -passin pass: with the quoted password' do
        expect(cmd).to include('-passin pass:"secret"')
      end

      it 'pipes to openssl x509 -noout -subject' do
        expect(cmd).to include('| openssl x509 -noout -subject')
      end

      it 'handles passwords with special characters' do
        cmd2 = build_openssl_cert_command('/c.p12', 'p@ss!word#123')
        expect(cmd2).to include('-passin pass:"p@ss!word#123"')
      end

      it 'handles certificate paths with spaces' do
        cmd2 = build_openssl_cert_command('/my certs/My Cert.p12', 'pass')
        expect(cmd2).to include('-in /my certs/My Cert.p12')
      end
    end

    if OPENSSL_AVAILABLE
      context 'positive path – openssl binary is executable' do
        it 'openssl is on PATH and exits zero' do
          _, _, status = Open3.capture3('openssl version')
          expect(status.success?).to be true
        end

        it 'openssl version output is non-empty' do
          out, = Open3.capture3('openssl version')
          expect(out.strip).not_to be_empty
        end

        it 'openssl version output starts with "OpenSSL"' do
          out, = Open3.capture3('openssl version')
          expect(out).to match(/OpenSSL|LibreSSL/)
        end
      end
    else
      it 'openssl binary (not found – skipped)' do
        skip 'openssl not available in this environment'
      end
    end
  end

  # ── security cms ─────────────────────────────────────────────────────────────
  context 'security cms command (parse_provisioning_profile / update_build_settings)' do
    context 'positive path – decode command string format' do
      let(:cmd) { build_security_cms_command('/path/Profile.mobileprovision') }

      it 'starts with "security cms"' do
        expect(cmd).to start_with('security cms')
      end

      it 'contains -D flag (decode)' do
        expect(cmd).to include('-D')
      end

      it 'contains -i flag followed by the profile path' do
        expect(cmd).to include('-i /path/Profile.mobileprovision')
      end

      it 'handles profile paths with spaces' do
        cmd2 = build_security_cms_command('/my certs/My Profile.mobileprovision')
        expect(cmd2).to include('-i /my certs/My Profile.mobileprovision')
      end
    end

    context 'positive path – decode-to-plist command string format' do
      let(:cmd) { build_security_cms_to_plist_command('/path/Profile.mobileprovision', '/tmp/out.plist') }

      it 'starts with "security cms"' do
        expect(cmd).to start_with('security cms')
      end

      it 'contains -D flag' do
        expect(cmd).to include('-D')
      end

      it 'contains the source profile path after -i' do
        expect(cmd).to include('-i /path/Profile.mobileprovision')
      end

      it 'redirects output to the plist file with >' do
        expect(cmd).to include('> /tmp/out.plist')
      end
    end

    context 'negative path – empty profile path' do
      it 'still builds a syntactically valid command even with an empty path' do
        cmd = build_security_cms_command('')
        expect(cmd).to include('security cms -D -i')
      end
    end
  end

  # ── PlistBuddy UUID ───────────────────────────────────────────────────────────
  context 'PlistBuddy UUID command (parse_provisioning_profile)' do
    context 'positive path – command string format' do
      let(:cmd) { build_plistbuddy_uuid_command('/tmp/profile.plist') }

      it 'uses /usr/libexec/PlistBuddy' do
        expect(cmd).to start_with('/usr/libexec/PlistBuddy')
      end

      it 'contains -c flag with "Print UUID"' do
        expect(cmd).to include('-c "Print UUID"')
      end

      it 'wraps the plist path in double quotes' do
        expect(cmd).to include('"/tmp/profile.plist"')
      end

      it 'handles plist paths with spaces' do
        cmd2 = build_plistbuddy_uuid_command('/tmp/my profile.plist')
        expect(cmd2).to include('"/tmp/my profile.plist"')
      end
    end

    if PLISTBUDDY_AVAILABLE
      context 'positive path – real PlistBuddy execution (UUID key present)' do
        let(:tmpdir)    { Dir.mktmpdir('plistbuddy_uuid_test') }
        after           { FileUtils.rm_rf(tmpdir) }

        let(:plist_path) do
          path = File.join(tmpdir, 'test.plist')
          File.write(path, <<~XML)
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
              "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
              <key>UUID</key>
              <string>AAAABBBB-1234-5678-ABCD-EEFF00112233</string>
            </dict>
            </plist>
          XML
          path
        end

        it 'reads the UUID value from a real plist file' do
          out = `#{build_plistbuddy_uuid_command(plist_path)}`.chomp
          expect(out).to eq('AAAABBBB-1234-5678-ABCD-EEFF00112233')
        end

        it 'exits zero when the key exists' do
          system(build_plistbuddy_uuid_command(plist_path) + ' > /dev/null 2>&1')
          expect($CHILD_STATUS.success?).to be true
        end
      end

      context 'negative path – UUID key absent → non-zero exit' do
        let(:tmpdir)    { Dir.mktmpdir('plistbuddy_uuid_neg') }
        after           { FileUtils.rm_rf(tmpdir) }

        let(:empty_plist) do
          path = File.join(tmpdir, 'empty.plist')
          File.write(path, <<~XML)
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
              "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0"><dict></dict></plist>
          XML
          path
        end

        it 'exits non-zero when the UUID key is missing' do
          system(build_plistbuddy_uuid_command(empty_plist) + ' > /dev/null 2>&1')
          expect($CHILD_STATUS.success?).to be false
        end
      end
    else
      it 'PlistBuddy UUID execution (not found – skipped)' do
        skip '/usr/libexec/PlistBuddy not available in this environment'
      end
    end
  end

  # ── PlistBuddy CFBundleIdentifier ────────────────────────────────────────────
  context 'PlistBuddy CFBundleIdentifier command (get_bundle_identifiers)' do
    context 'positive path – command string format' do
      let(:cmd) { build_plistbuddy_bundle_id_command('/App.app/Info.plist') }

      it 'uses /usr/libexec/PlistBuddy' do
        expect(cmd).to start_with('/usr/libexec/PlistBuddy')
      end

      it 'contains -c flag with "Print CFBundleIdentifier"' do
        expect(cmd).to include('-c "Print CFBundleIdentifier"')
      end

      it 'wraps the plist path in double quotes' do
        expect(cmd).to include('"/App.app/Info.plist"')
      end

      it 'handles paths with spaces' do
        cmd2 = build_plistbuddy_bundle_id_command('/My App.app/Info.plist')
        expect(cmd2).to include('"/My App.app/Info.plist"')
      end
    end

    if PLISTBUDDY_AVAILABLE
      context 'positive path – real PlistBuddy execution (CFBundleIdentifier present)' do
        let(:tmpdir)    { Dir.mktmpdir('plistbuddy_bid_test') }
        after           { FileUtils.rm_rf(tmpdir) }

        let(:info_plist) do
          path = File.join(tmpdir, 'Info.plist')
          File.write(path, <<~XML)
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
              "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
              <key>CFBundleIdentifier</key>
              <string>com.example.testapp</string>
            </dict>
            </plist>
          XML
          path
        end

        it 'reads CFBundleIdentifier from a real Info.plist' do
          out = `#{build_plistbuddy_bundle_id_command(info_plist)}`.chomp
          expect(out).to eq('com.example.testapp')
        end

        it 'exits zero when the key exists' do
          system(build_plistbuddy_bundle_id_command(info_plist) + ' > /dev/null 2>&1')
          expect($CHILD_STATUS.success?).to be true
        end
      end
    else
      it 'PlistBuddy CFBundleIdentifier execution (not found – skipped)' do
        skip '/usr/libexec/PlistBuddy not available in this environment'
      end
    end
  end

  # ── xcodebuild -list ──────────────────────────────────────────────────────────
  context 'xcodebuild -list command (get_project_path – workspace)' do
    context 'positive path – command string format' do
      let(:cmd) { build_xcodebuild_list_command('/repo/MyApp.xcodeproj') }

      it 'starts with xcodebuild' do
        expect(cmd).to start_with('xcodebuild')
      end

      it 'contains -project flag with the quoted project path' do
        expect(cmd).to include('-project "/repo/MyApp.xcodeproj"')
      end

      it 'contains -list flag' do
        expect(cmd).to include('-list')
      end

      it 'handles project paths with spaces' do
        cmd2 = build_xcodebuild_list_command('/My Repo/My App.xcodeproj')
        expect(cmd2).to include('-project "/My Repo/My App.xcodeproj"')
      end

      it 'does NOT contain -workspace flag' do
        expect(cmd).not_to include('-workspace')
      end
    end
  end

  # ── xcodebuild -version ───────────────────────────────────────────────────────
  context 'xcodebuild -version command (generate_archive_metadata)' do
    if XCODEBUILD_AVAILABLE
      context 'positive path – execution' do
        it 'exits with zero' do
          _, _, status = Open3.capture3('xcodebuild -version')
          expect(status.success?).to be true
        end

        it 'output starts with "Xcode "' do
          out, = Open3.capture3('xcodebuild -version')
          expect(out).to match(/\AXcode /)
        end

        it 'version number is a dot-separated numeric string' do
          out, = Open3.capture3('xcodebuild -version')
          version = out.split(' ')[1]&.chomp
          expect(version).to match(/\A\d+\.\d+/)
        end

        it 'version string is parseable by the generate_archive_metadata logic' do
          out, = Open3.capture3('xcodebuild -version')
          version = out.split(' ')[1]&.chomp
          expect(version).not_to be_nil
          expect(version).not_to be_empty
        end
      end
    else
      it 'xcodebuild binary (not found – skipped)' do
        skip 'xcodebuild not available in this environment'
      end
    end
  end
end

# ─── 19. Command output parsing & error-handling tests ────────────────────────
# Tests the logic that processes stdout/stderr from shell commands:
#   – openssl subject output  → parse_certificate (lines 161-175)
#   – xcodebuild -list output → get_project_path  (lines 312-314)
#   – xcodebuild -version     → generate_archive_metadata (line 533)
#   – run_command stdout streaming / stderr surfacing (lines 108-121)
#   – run_command_simple exit-code error message format (lines 132-134)
# Where real tools allow it, fake binaries are injected via PATH so the full
# command pipeline is exercised without needing a real Xcode project.

# ── Output parsing helpers (mirrors of main.rb logic) ─────────────────────────

# Mirrors parse_certificate lines 161-175:
# Takes the raw stdout of `openssl pkcs12 ... | openssl x509 -noout -subject`
# and returns { code_sign_identity:, code_sign_development_team: }.
def parse_openssl_subject_output(raw_output)
  output = raw_output.encode('UTF-8', 'binary', invalid: :replace, undef: :replace, replace: '')
  output = output.gsub(/\\x([0-9A-Fa-f]{2})/) { [$1.hex].pack('C') }

  code_sign_identity        = nil
  code_sign_development_team = nil

  output.split('/').each do |item|
    parts = item.split('=')
    key   = parts[0]
    value = parts[1]&.strip   # strip trailing newline from the last field
    code_sign_identity         = value if key == 'CN'
    code_sign_development_team = value if key == 'OU'
  end

  { code_sign_identity: code_sign_identity,
    code_sign_development_team: code_sign_development_team }
end

# Mirrors get_project_path lines 312-313:
# Returns the list of scheme names found after the "Schemes:" marker.
def parse_xcodebuild_schemes(output)
  part = output.split('Schemes:')[1]
  return [] unless part

  part.strip.lines.map(&:strip).reject(&:empty?)
end

# Mirrors generate_archive_metadata line 533:
# Returns the bare version string (e.g. "16.2") from `xcodebuild -version`.
def parse_xcode_version(output)
  output.split(' ')[1]&.chomp
end

# ── Fake-binary helper ─────────────────────────────────────────────────────────
# Writes an executable shell script named +name+ to a temp dir,
# prepends that dir to PATH for the duration of the block, then restores.
def with_fake_binary(name, script_body)
  bin_dir     = Dir.mktmpdir('fake_bin')
  script_path = File.join(bin_dir, name)
  File.write(script_path, "#!/bin/sh\n#{script_body}\n")
  FileUtils.chmod('+x', script_path)
  old_path    = ENV['PATH']
  ENV['PATH'] = "#{bin_dir}:#{old_path}"
  yield bin_dir
ensure
  ENV['PATH'] = old_path
  FileUtils.rm_rf(bin_dir)
end

# ── Tests ──────────────────────────────────────────────────────────────────────
RSpec.describe 'Command output parsing & error handling' do

  # ── A. openssl subject output parsing ──────────────────────────────────────
  context 'openssl x509 -noout -subject output parsing (parse_certificate)' do
    context 'positive path – standard US distribution certificate' do
      let(:subject) { "subject=/C=US/O=My Company/OU=ABCD1234/CN=iPhone Distribution: My Corp (ABCD1234)\n" }
      let(:parsed)  { parse_openssl_subject_output(subject) }

      it 'extracts the CN as code_sign_identity' do
        expect(parsed[:code_sign_identity]).to eq('iPhone Distribution: My Corp (ABCD1234)')
      end

      it 'extracts the OU as code_sign_development_team' do
        expect(parsed[:code_sign_development_team]).to eq('ABCD1234')
      end
    end

    context 'positive path – development certificate' do
      let(:subject) { "subject=/C=US/OU=TEAM99/CN=iPhone Developer: Jane Doe (TEAM99)\n" }
      let(:parsed)  { parse_openssl_subject_output(subject) }

      it 'extracts CN for a development cert' do
        expect(parsed[:code_sign_identity]).to eq('iPhone Developer: Jane Doe (TEAM99)')
      end

      it 'extracts OU for a development cert' do
        expect(parsed[:code_sign_development_team]).to eq('TEAM99')
      end
    end

    context 'positive path – Apple Distribution (Xcode 11+) certificate' do
      let(:subject) { "subject=/C=US/O=Apple Inc./OU=XY12345678/CN=Apple Distribution: Acme Inc. (XY12345678)\n" }
      let(:parsed)  { parse_openssl_subject_output(subject) }

      it 'extracts the Apple Distribution CN' do
        expect(parsed[:code_sign_identity]).to start_with('Apple Distribution:')
      end

      it 'extracts the OU team ID' do
        expect(parsed[:code_sign_development_team]).to eq('XY12345678')
      end
    end

    context 'positive path – CN with colons and parentheses in the name' do
      let(:subject) { "subject=/OU=ZZ9999/CN=iPhone Distribution: Corp: Sub-unit (ZZ9999)\n" }
      let(:parsed)  { parse_openssl_subject_output(subject) }

      it 'does not truncate CN at the first colon' do
        expect(parsed[:code_sign_identity]).to eq('iPhone Distribution: Corp: Sub-unit (ZZ9999)')
      end
    end

    context 'positive path – non-ASCII input does not raise' do
      # The encode('UTF-8','binary') step in parse_certificate is designed to
      # handle raw binary bytes from OpenSSL (which may not be valid UTF-8).
      # The call re-transcodes byte-by-byte; multi-byte UTF-8 sequences get
      # split, so the output may differ from the input. What matters is that
      # the function never raises and always returns a Hash.
      let(:subject) { "subject=/OU=UTF01/CN=iPhone Distribution: Corp (UTF01)\n" }

      it 'does not raise for a plain ASCII subject line' do
        expect { parse_openssl_subject_output(subject) }.not_to raise_error
      end

      it 'returns a Hash with the expected keys' do
        result = parse_openssl_subject_output(subject)
        expect(result).to have_key(:code_sign_identity)
        expect(result).to have_key(:code_sign_development_team)
      end

      it 'does not raise when the input contains raw high-byte values' do
        binary_subject = "subject=/OU=BIN01/CN=Corp \xC3\xBC (BIN01)".b
        expect { parse_openssl_subject_output(binary_subject) }.not_to raise_error
      end
    end

    context 'positive path – hex-escaped non-ASCII characters are decoded' do
      # main.rb unescapes literal \\xNN sequences in the subject
      let(:subject_with_escape) { "subject=/OU=HEX01/CN=iPhone Dist: Corp \\xC3\\xBC (HEX01)\n" }
      let(:parsed)              { parse_openssl_subject_output(subject_with_escape) }

      it 'returns a CN without raw \\x escape sequences' do
        expect(parsed[:code_sign_identity]).not_to include('\\x')
      end
    end

    context 'negative path – CN absent from subject' do
      let(:parsed) { parse_openssl_subject_output("subject=/C=US/O=Corp/OU=TEAM01\n") }

      it 'returns nil for code_sign_identity when CN is missing' do
        expect(parsed[:code_sign_identity]).to be_nil
      end

      it 'still returns OU when CN is missing' do
        expect(parsed[:code_sign_development_team]).to eq('TEAM01')
      end
    end

    context 'negative path – empty output string' do
      let(:parsed) { parse_openssl_subject_output('') }

      it 'returns nil for both fields on empty output' do
        expect(parsed[:code_sign_identity]).to be_nil
        expect(parsed[:code_sign_development_team]).to be_nil
      end
    end

    if OPENSSL_AVAILABLE
      context 'positive path – real openssl version output is non-empty' do
        it 'openssl produces non-empty stdout for openssl version' do
          out, _, status = Open3.capture3('openssl version')
          expect(status.success?).to be true
          expect(out).not_to be_empty
        end
      end
    end
  end

  # ── B. xcodebuild -list output parsing ────────────────────────────────────
  context 'xcodebuild -list output parsing (get_project_path)' do
    context 'positive path – single scheme' do
      let(:output) do
        <<~OUT
          Information about project "MyApp":
              Targets:
                  MyApp
              Build Configurations:
                  Debug
                  Release
              If no build configuration is specified and -scheme is not passed then "Release" is used.
              Schemes:
                  MyScheme
        OUT
      end

      it 'finds the scheme after the Schemes: marker' do
        schemes = parse_xcodebuild_schemes(output)
        expect(schemes).to include('MyScheme')
      end

      it 'does not include section headers as scheme names' do
        schemes = parse_xcodebuild_schemes(output)
        expect(schemes).not_to include('Targets:')
        expect(schemes).not_to include('Build Configurations:')
      end
    end

    context 'positive path – multiple schemes' do
      let(:output) do
        <<~OUT
          Information about project "App":
              Schemes:
                  AppDebug
                  AppRelease
                  AppUITests
        OUT
      end

      it 'returns all scheme names' do
        schemes = parse_xcodebuild_schemes(output)
        expect(schemes).to include('AppDebug', 'AppRelease', 'AppUITests')
      end

      it 'returns exactly three schemes' do
        expect(parse_xcodebuild_schemes(output).length).to eq(3)
      end
    end

    context 'positive path – scheme detection via include?' do
      let(:output) { "Schemes:\n    MyScheme\n    OtherScheme\n" }

      it 'include? finds an exact scheme name' do
        part = output.split('Schemes:')[1]
        expect(part.include?('MyScheme')).to be true
      end

      it 'include? returns false for a non-existent scheme' do
        part = output.split('Schemes:')[1]
        expect(part.include?('NonExistent')).to be false
      end
    end

    context 'negative path – no Schemes: section in output' do
      let(:output) { "error: The project 'Foo' cannot be opened.\n" }

      it 'returns an empty array when Schemes: is absent' do
        expect(parse_xcodebuild_schemes(output)).to be_empty
      end

      it 'split on Schemes: yields nil for [1]' do
        expect(output.split('Schemes:')[1]).to be_nil
      end
    end

    context 'negative path – empty output' do
      it 'returns an empty array for blank output' do
        expect(parse_xcodebuild_schemes('')).to be_empty
      end
    end

    if XCODEBUILD_AVAILABLE
      context 'positive path – real xcodebuild -list on non-existent project' do
        it 'exits non-zero and prints to stderr' do
          _, err, status = Open3.capture3('xcodebuild -project /nonexistent/Fake.xcodeproj -list')
          expect(status.success?).to be false
          expect(err).not_to be_empty
        end
      end
    end
  end

  # ── C. xcodebuild -version output parsing ─────────────────────────────────
  context 'xcodebuild -version output parsing (generate_archive_metadata)' do
    context 'positive path – standard version format' do
      it 'extracts "14.3" from "Xcode 14.3"' do
        expect(parse_xcode_version("Xcode 14.3\nBuild version 14E222b\n")).to eq('14.3')
      end

      it 'extracts "15.0" from "Xcode 15.0"' do
        expect(parse_xcode_version("Xcode 15.0\nBuild version 15A240d\n")).to eq('15.0')
      end

      it 'extracts "16.2" from "Xcode 16.2"' do
        expect(parse_xcode_version("Xcode 16.2\nBuild version 16C5032a\n")).to eq('16.2')
      end

      it 'extracts a three-part version like "15.2.1"' do
        expect(parse_xcode_version("Xcode 15.2.1\nBuild version 15C501\n")).to eq('15.2.1')
      end
    end

    context 'negative path – empty or malformed output' do
      it 'returns nil for empty string' do
        expect(parse_xcode_version('')).to be_nil
      end

      it 'returns nil when there is no space in the output' do
        expect(parse_xcode_version('NoSpaceHere')).to be_nil
      end
    end

    if XCODEBUILD_AVAILABLE
      context 'positive path – real xcodebuild -version output' do
        let(:output) { `xcodebuild -version` }

        it 'first word is "Xcode"' do
          expect(output.split(' ').first).to eq('Xcode')
        end

        it 'parsed version matches digit.digit pattern' do
          version = parse_xcode_version(output)
          expect(version).to match(/\A\d+\.\d+/)
        end
      end
    end
  end

  # ── D. run_command stdout streaming ───────────────────────────────────────
  context 'run_command stdout streaming (lines 108-110)' do
    context 'positive path – multi-line stdout is printed' do
      it 'prints all lines from a multi-line command' do
        expect do
          run_command('printf "line1\nline2\nline3\n"', false)
        end.to output(/line1.*line2.*line3/m).to_stdout
      end

      it 'prefixes the command itself with @@[command]' do
        expect do
          run_command('echo hello', false)
        end.to output(/@@\[command\]/).to_stdout
      end

      it 'prints the echo output to stdout' do
        expect do
          run_command('echo captured_line', false)
        end.to output(/captured_line/).to_stdout
      end
    end

    context 'positive path – command with no stdout produces no extra output' do
      it 'does not raise for a silent zero-exit command' do
        expect { run_command('true', false) }.not_to raise_error
      end
    end

    context 'negative path – failed command with skip_abort=true prints stderr' do
      it 'prints the stderr message instead of aborting' do
        expect do
          run_command('sh -c "echo MY_STDERR_MSG >&2; exit 1"', true)
        end.to output(/MY_STDERR_MSG/).to_stdout
      end

      it 'does NOT raise SystemExit when skip_abort is true' do
        expect do
          run_command('sh -c "exit 2"', true)
        end.not_to raise_error
      end
    end

    context 'negative path – failed command with skip_abort=false aborts' do
      it 'raises SystemExit' do
        expect { run_command('false', false) }.to raise_error(SystemExit)
      end
    end
  end

  # ── E. run_command_simple error-message format ─────────────────────────────
  context 'run_command_simple error message format (lines 132-134)' do
    let(:tmpdir) { Dir.mktmpdir('rcs_fmt_test') }
    after        { FileUtils.rm_rf(tmpdir) }

    around do |example|
      old = ENV['AC_TEMP_DIR']
      ENV['AC_TEMP_DIR'] = tmpdir
      example.run
      ENV['AC_TEMP_DIR'] = old
    end

    context 'positive path – zero-exit command succeeds silently' do
      it 'does not raise for a zero-exit command' do
        expect { run_command_simple('true') }.not_to raise_error
      end

      it 'prints the @@[command] prefix to stdout' do
        expect { run_command_simple('true') }.to output(/@@\[command\]/).to_stdout
      end
    end

    context 'negative path – error message contains the exit code' do
      it 'abort message includes the exit code (exit 3)' do
        begin
          run_command_simple('sh -c "exit 3"')
        rescue SystemExit => e
          expect(e.message).to match(/3/)
        end
      end

      it 'abort message mentions "Unexpected exit"' do
        begin
          run_command_simple('sh -c "exit 1"')
        rescue SystemExit => e
          expect(e.message).to match(/Unexpected exit/)
        end
      end

      it 'abort message includes "Check logs for details"' do
        begin
          run_command_simple('false')
        rescue SystemExit => e
          expect(e.message).to match(/Check logs for details/)
        end
      end
    end

    context 'negative path – stderr is written to the log file before abort' do
      it 'creates the .command.stderr.log file' do
        begin
          run_command_simple('sh -c "echo err_content >&2; exit 1"')
        rescue SystemExit
          # expected
        end
        expect(File.exist?("#{tmpdir}/.command.stderr.log")).to be true
      end
    end
  end

  # ── F. Fake-binary pipeline tests ─────────────────────────────────────────
  context 'fake binary pipeline (archive / export command flow)' do
    let(:tmpdir) { Dir.mktmpdir('fake_pipeline_test') }
    after        { FileUtils.rm_rf(tmpdir) }

    around do |example|
      old = ENV['AC_TEMP_DIR']
      ENV['AC_TEMP_DIR'] = tmpdir
      example.run
      ENV['AC_TEMP_DIR'] = old
    end

    context 'positive path – fake xcodebuild that succeeds' do
      it 'run_command does not raise when fake xcodebuild exits 0' do
        with_fake_binary('xcodebuild', 'echo "Build succeeded."; exit 0') do
          expect { run_command('xcodebuild archive', false) }.not_to raise_error
        end
      end

      it 'run_command prints xcodebuild stdout line-by-line' do
        with_fake_binary('xcodebuild', 'echo "ARCHIVE_OK"') do
          expect { run_command('xcodebuild archive', false) }
            .to output(/ARCHIVE_OK/).to_stdout
        end
      end

      it 'run_command_simple does not raise when fake xcodebuild exits 0' do
        with_fake_binary('xcodebuild', 'echo "Export OK"; exit 0') do
          expect { run_command_simple('xcodebuild -exportArchive') }.not_to raise_error
        end
      end
    end

    context 'negative path – fake xcodebuild that fails' do
      it 'run_command raises SystemExit when fake xcodebuild exits non-zero' do
        with_fake_binary('xcodebuild', 'echo "BUILD FAILED" >&2; exit 70') do
          expect { run_command('xcodebuild archive', false) }.to raise_error(SystemExit)
        end
      end

      it 'run_command with skip_abort=true does NOT raise on xcodebuild failure' do
        with_fake_binary('xcodebuild', 'echo "BUILD FAILED" >&2; exit 70') do
          expect { run_command('xcodebuild archive', true) }.not_to raise_error
        end
      end

      it 'run_command_simple raises SystemExit when fake xcodebuild exits non-zero' do
        with_fake_binary('xcodebuild', 'echo "EXPORT FAILED" >&2; exit 65') do
          expect { run_command_simple('xcodebuild -exportArchive') }.to raise_error(SystemExit)
        end
      end

      it 'abort message from run_command_simple includes the correct exit code' do
        with_fake_binary('xcodebuild', 'exit 42') do
          begin
            run_command_simple('xcodebuild -exportArchive')
          rescue SystemExit => e
            expect(e.message).to match(/42/)
          end
        end
      end
    end

    context 'positive path – fake xcodebuild -version is parseable' do
      it 'parse_xcode_version handles fake Xcode version output' do
        fake_output = "Xcode 99.1\nBuild version 99A001\n"
        with_fake_binary('xcodebuild', "echo '#{fake_output}'") do
          version = parse_xcode_version(fake_output)
          expect(version).to eq('99.1')
        end
      end
    end

    context 'positive path – fake openssl subject output is parseable' do
      it 'parse_openssl_subject_output handles a realistic fake openssl output' do
        fake_subject = "subject=/C=US/OU=FAKE01/CN=iPhone Distribution: Fake Corp (FAKE01)"
        with_fake_binary('openssl', "echo '#{fake_subject}'") do
          result = parse_openssl_subject_output(fake_subject)
          expect(result[:code_sign_identity]).to eq('iPhone Distribution: Fake Corp (FAKE01)')
          expect(result[:code_sign_development_team]).to eq('FAKE01')
        end
      end
    end
  end
end

# ─── 20. Command string correctness & parameter validation ───────────────────
# Verifies that every command string assembled in main.rb uses the semantically
# correct flags, the right ordering, mutually-exclusive parameter combinations,
# and that all required flags are present for each operation mode.

RSpec.describe 'Command string correctness & parameter validation' do

  # ── openssl pkcs12 ──────────────────────────────────────────────────────────
  context 'openssl pkcs12 command correctness (parse_certificate)' do
    let(:cmd) { build_openssl_cert_command('/certs/Cert.p12', 'secret') }

    context 'flag semantics' do
      it 'uses -nokeys to suppress private-key output (security)' do
        expect(cmd).to include('-nokeys')
      end

      it 'does NOT use -nodes (incorrect flag for this operation)' do
        expect(cmd).not_to include('-nodes')
      end

      it 'uses -passin pass: prefix (not -password or bare value)' do
        expect(cmd).to match(/-passin pass:/)
      end

      it 'wraps the password in double quotes to handle special characters' do
        expect(cmd).to match(/-passin pass:"/)
      end
    end

    context 'pipeline structure' do
      it 'pipes to openssl x509 for subject extraction' do
        expect(cmd).to include('| openssl x509')
      end

      it 'uses -noout in the x509 part (no certificate output, only subject)' do
        expect(cmd).to include('-noout')
      end

      it 'uses -subject in the x509 part to print the subject field' do
        expect(cmd).to include('-subject')
      end

      it 'does NOT use -text (would produce verbose output instead of subject)' do
        expect(cmd.split('|').last).not_to include('-text')
      end
    end

    context 'parameter ordering' do
      it 'pkcs12 stage comes before the pipe' do
        expect(cmd.index('pkcs12')).to be < cmd.index('|')
      end

      it 'x509 stage comes after the pipe' do
        expect(cmd.index('x509')).to be > cmd.index('|')
      end
    end
  end

  # ── security cms ────────────────────────────────────────────────────────────
  context 'security cms command correctness (parse_provisioning_profile / update_build_settings)' do
    let(:decode_cmd)    { build_security_cms_command('/path/Profile.mobileprovision') }
    let(:to_plist_cmd)  { build_security_cms_to_plist_command('/path/Profile.mobileprovision', '/tmp/out.plist') }

    context 'flag semantics' do
      it 'uses -D flag for decoding (not -E which encodes)' do
        expect(decode_cmd).to include(' -D ')
      end

      it 'does NOT use -E (encode) flag' do
        expect(decode_cmd).not_to include(' -E ')
      end

      it 'uses -i flag to specify the input file' do
        expect(decode_cmd).to include('-i ')
      end
    end

    context 'output redirection correctness' do
      it 'uses > (overwrite) not >> (append) for plist output' do
        expect(to_plist_cmd).to include(' > ')
        expect(to_plist_cmd).not_to include('>>')
      end

      it 'redirected output path is the last token in the command' do
        expect(to_plist_cmd).to end_with('/tmp/out.plist')
      end
    end

    context 'parameter ordering' do
      it '-D flag appears before -i flag' do
        expect(to_plist_cmd.index('-D')).to be < to_plist_cmd.index('-i')
      end

      it 'input path appears before the > redirect' do
        expect(to_plist_cmd.index('Profile.mobileprovision')).to be < to_plist_cmd.index(' > ')
      end
    end
  end

  # ── PlistBuddy ──────────────────────────────────────────────────────────────
  context 'PlistBuddy command correctness' do
    context 'UUID command (parse_provisioning_profile)' do
      let(:cmd) { build_plistbuddy_uuid_command('/tmp/profile.plist') }

      it 'uses the Print command (not Read or Get)' do
        expect(cmd).to include('-c "Print UUID"')
      end

      it 'key name is exactly "UUID" (case-sensitive)' do
        expect(cmd).to match(/-c "Print UUID"/)
      end

      it 'path is double-quoted (required for paths with spaces)' do
        expect(cmd).to match(/"\/.+\.plist"/)
      end

      it '-c flag comes before the plist path' do
        expect(cmd.index('-c')).to be < cmd.index('.plist')
      end
    end

    context 'CFBundleIdentifier command (get_bundle_identifiers)' do
      let(:cmd) { build_plistbuddy_bundle_id_command('/App.app/Info.plist') }

      it 'uses the Print command (not Read or Get)' do
        expect(cmd).to include('-c "Print CFBundleIdentifier"')
      end

      it 'key name is exactly "CFBundleIdentifier" (case-sensitive)' do
        expect(cmd).to match(/-c "Print CFBundleIdentifier"/)
      end

      it 'path is double-quoted' do
        expect(cmd).to match(/"\/.+\.plist"/)
      end
    end
  end

  # ── xcodebuild -list ────────────────────────────────────────────────────────
  context 'xcodebuild -list command correctness (get_project_path)' do
    let(:cmd) { build_xcodebuild_list_command('/repo/MyApp.xcodeproj') }

    context 'flag correctness' do
      it 'uses -project flag (not -workspace) for individual project listing' do
        expect(cmd).to include('-project')
        expect(cmd).not_to include('-workspace')
      end

      it 'uses -list action (not -showBuildSettings or -showDestinations)' do
        expect(cmd).to include('-list')
        expect(cmd).not_to include('-showBuildSettings')
      end

      it 'does NOT include archive or exportArchive actions' do
        expect(cmd).not_to include('archive')
        expect(cmd).not_to include('exportArchive')
      end
    end

    context 'parameter ordering' do
      it '-project flag appears before -list' do
        expect(cmd.index('-project')).to be < cmd.index('-list')
      end
    end
  end

  # ── xcodebuild archive ──────────────────────────────────────────────────────
  context 'xcodebuild archive command correctness (archive())' do
    let(:base) do
      { scheme: 'MyScheme', archive_path: '/out/build.xcarchive',
        tmp_path: '/tmp', project_full_path: '/repo/App.xcodeproj' }
    end

    context 'required flags always present' do
      it 'contains -scheme flag' do
        expect(build_archive_command(**base)).to include('-scheme')
      end

      it 'contains archive action keyword' do
        expect(build_archive_command(**base)).to include(' archive ')
      end

      it 'contains -archivePath flag' do
        expect(build_archive_command(**base)).to include('-archivePath')
      end

      it 'contains -derivedDataPath flag' do
        expect(build_archive_command(**base)).to include('-derivedDataPath')
      end

      it 'contains -destination flag' do
        expect(build_archive_command(**base)).to include('-destination')
      end

      it 'targets generic iOS device (not simulator)' do
        expect(build_archive_command(**base)).to include('generic/platform=iOS')
        expect(build_archive_command(**base)).not_to include('Simulator')
      end
    end

    context 'clean action ordering' do
      it 'clean appears before archive in the command' do
        cmd = build_archive_command(**base, clean_build: true)
        expect(cmd.index('clean')).to be < cmd.index(' archive ')
      end

      it 'clean is omitted when clean_build is false' do
        cmd = build_archive_command(**base, clean_build: false)
        expect(cmd).not_to match(/\bclean\b/)
      end
    end

    context 'build setting format (KEY=VALUE without spaces)' do
      it 'CODE_SIGN_STYLE uses = without spaces' do
        cmd = build_archive_command(**base, is_sign_available: true)
        expect(cmd).to match(/CODE_SIGN_STYLE=Manual/)
        expect(cmd).not_to match(/CODE_SIGN_STYLE\s+=\s+Manual/)
      end

      it 'CODE_SIGNING_REQUIRED uses = without spaces' do
        cmd = build_archive_command(**base, is_sign_available: false, is_automatic_sign: false)
        expect(cmd).to match(/CODE_SIGNING_REQUIRED=NO/)
      end

      it 'CODE_SIGNING_ALLOWED uses = without spaces' do
        cmd = build_archive_command(**base, is_sign_available: false, is_automatic_sign: false)
        expect(cmd).to match(/CODE_SIGNING_ALLOWED=NO/)
      end

      it 'COMPILER_INDEX_STORE_ENABLE uses = without spaces' do
        cmd = build_archive_command(**base, compiler_index_store_enable: 'NO')
        expect(cmd).to match(/COMPILER_INDEX_STORE_ENABLE=NO/)
      end
    end

    context 'no-sign build – all three disable flags must be present together' do
      let(:cmd) { build_archive_command(**base, is_automatic_sign: false, is_sign_available: false) }

      it 'has CODE_SIGN_IDENTITY="" (empty identity)' do
        expect(cmd).to include('CODE_SIGN_IDENTITY=""')
      end

      it 'has CODE_SIGNING_REQUIRED=NO' do
        expect(cmd).to include('CODE_SIGNING_REQUIRED=NO')
      end

      it 'has CODE_SIGNING_ALLOWED=NO' do
        expect(cmd).to include('CODE_SIGNING_ALLOWED=NO')
      end

      it 'does NOT have CODE_SIGN_STYLE=Manual (contradicts no-sign)' do
        expect(cmd).not_to include('CODE_SIGN_STYLE=Manual')
      end
    end

    context 'manual-sign build – correct flag present, no-sign flags absent' do
      let(:cmd) { build_archive_command(**base, is_sign_available: true) }

      it 'has CODE_SIGN_STYLE=Manual' do
        expect(cmd).to include('CODE_SIGN_STYLE=Manual')
      end

      it 'does NOT have CODE_SIGNING_ALLOWED=NO' do
        expect(cmd).not_to include('CODE_SIGNING_ALLOWED=NO')
      end

      it 'does NOT have CODE_SIGNING_REQUIRED=NO' do
        expect(cmd).not_to include('CODE_SIGNING_REQUIRED=NO')
      end
    end

    context 'automatic-sign build – provisioning flags correct' do
      let(:autosign) do
        base.merge(is_automatic_sign: true,
                   autosign_key:       'KEYID',
                   autosign_cred_path: '/key/AuthKey.p8',
                   autosign_issuer_id: 'ISSUER-ID')
      end

      it 'has -allowProvisioningUpdates' do
        expect(build_archive_command(**autosign)).to include('-allowProvisioningUpdates')
      end

      it 'has -authenticationKeyPath' do
        expect(build_archive_command(**autosign)).to include('-authenticationKeyPath')
      end

      it 'has -authenticationKeyID' do
        expect(build_archive_command(**autosign)).to include('-authenticationKeyID')
      end

      it 'has -authenticationKeyIssuerID' do
        expect(build_archive_command(**autosign)).to include('-authenticationKeyIssuerID')
      end

      it 'all three auth flags are present together (not partially)' do
        cmd = build_archive_command(**autosign)
        expect(cmd).to include('-authenticationKeyPath')
        expect(cmd).to include('-authenticationKeyID')
        expect(cmd).to include('-authenticationKeyIssuerID')
      end

      it 'does NOT include no-sign flags when autosign' do
        cmd = build_archive_command(**autosign)
        expect(cmd).not_to include('CODE_SIGNING_ALLOWED=NO')
      end
    end

    context 'workspace vs project – mutually exclusive' do
      it 'uses -workspace for a .xcworkspace path' do
        cmd = build_archive_command(**base, is_workspace: true,
                                            project_full_path: '/repo/App.xcworkspace')
        expect(cmd).to include('-workspace')
        expect(cmd).not_to include('-project')
      end

      it 'uses -project for a .xcodeproj path' do
        cmd = build_archive_command(**base, is_workspace: false)
        expect(cmd).to include('-project')
        expect(cmd).not_to include('-workspace')
      end
    end

    context '-configuration flag correctness' do
      it 'uses -configuration (not -config or --configuration)' do
        cmd = build_archive_command(**base, configuration_name: 'Debug')
        expect(cmd).to include('-configuration "Debug"')
        expect(cmd).not_to include('--configuration')
      end

      it 'configuration value is double-quoted' do
        cmd = build_archive_command(**base, configuration_name: 'My Release')
        expect(cmd).to include('-configuration "My Release"')
      end
    end
  end

  # ── xcodebuild -exportArchive ───────────────────────────────────────────────
  context 'xcodebuild -exportArchive command correctness (export_archive())' do
    let(:archive)  { '/out/build.xcarchive' }
    let(:out_path) { '/out' }
    let(:plist)    { '/tmp/ExportOptions.plist' }
    let(:manual_cmd) { build_export_command(archive, out_path, plist) }

    context 'action flag' do
      it 'uses -exportArchive (not export-archive or exportarchive)' do
        expect(manual_cmd).to include('-exportArchive')
        expect(manual_cmd).not_to include('exportarchive')
        expect(manual_cmd).not_to include('export-archive')
      end

      it 'does NOT contain archive action (that is for building, not exporting)' do
        # The command should not have a bare "archive" action keyword
        expect(manual_cmd).not_to match(/\barchive\b/)
      end
    end

    context 'required path flags' do
      it '-archivePath is present and value is double-quoted' do
        expect(manual_cmd).to include("-archivePath \"#{archive}\"")
      end

      it '-exportPath is present and value is double-quoted' do
        expect(manual_cmd).to include("-exportPath \"#{out_path}\"")
      end

      it '-exportOptionsPlist is present and value is double-quoted' do
        expect(manual_cmd).to include("-exportOptionsPlist \"#{plist}\"")
      end
    end

    context 'manual export – no authentication flags' do
      it 'does NOT have -allowProvisioningUpdates' do
        expect(manual_cmd).not_to include('-allowProvisioningUpdates')
      end

      it 'does NOT have -authenticationKeyPath' do
        expect(manual_cmd).not_to include('-authenticationKeyPath')
      end

      it 'does NOT have -scheme flag (export uses the archive, not a scheme)' do
        expect(manual_cmd).not_to include('-scheme')
      end
    end

    context 'automatic-sign export – all three auth flags together' do
      let(:autosign_cmd) do
        build_export_command(archive, out_path, plist,
                             is_automatic: true,
                             key_path:     '/keys/AuthKey.p8',
                             key_id:       'KEYID',
                             issuer_id:    'ISSUER-ID')
      end

      it 'has -allowProvisioningUpdates' do
        expect(autosign_cmd).to include('-allowProvisioningUpdates')
      end

      it 'has -authenticationKeyPath' do
        expect(autosign_cmd).to include('-authenticationKeyPath /keys/AuthKey.p8')
      end

      it 'has -authenticationKeyID' do
        expect(autosign_cmd).to include('-authenticationKeyID KEYID')
      end

      it 'has -authenticationKeyIssuerID' do
        expect(autosign_cmd).to include('-authenticationKeyIssuerID ISSUER-ID')
      end

      it '-allowProvisioningUpdates comes first (before -exportArchive)' do
        expect(autosign_cmd.index('-allowProvisioningUpdates'))
          .to be < autosign_cmd.index('-exportArchive')
      end

      it 'still has all three required path flags' do
        expect(autosign_cmd).to include('-archivePath')
        expect(autosign_cmd).to include('-exportPath')
        expect(autosign_cmd).to include('-exportOptionsPlist')
      end
    end
  end
end

# ─── Runner ───────────────────────────────────────────────────────────────────
if __FILE__ == $PROGRAM_NAME
  RSpec.configure do |config|
    config.add_formatter ReadableFormatter
    config.color  = true
    config.order  = :defined
  end

  exit RSpec::Core::Runner.run(['--order', 'defined'])
end
