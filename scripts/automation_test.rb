# Exercise the actual automation shell without downloading or running external binaries.
require "minitest/autorun"
require "yaml"
require "digest"
require "tmpdir"
require "open3"
require "fileutils"

class AutomationTest < Minitest::Test
  ROOT = File.expand_path("..", __dir__)
  GITLEAKS_SHA = "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"

  def test_executable_actions_are_commit_pinned
    refs = Dir[File.join(ROOT, ".github/workflows/*.yml")].flat_map do |file|
      File.read(file).scan(/\buses:\s*([^\s#]+)/).flatten
    end
    refute_empty refs
    refs.each { |ref| assert_match(/\A[\w.\/-]+@[0-9a-f]{40}\z/, ref) unless ref.start_with?("./") }
  end

  %w[valid tampered missing failed].each do |download|
    define_method("test_gitleaks_#{download}_download") do
      workflow = YAML.load_file(File.join(ROOT, ".github/workflows/security.yml"))
      script = workflow["jobs"]["secrets"]["steps"].find { |step| step["name"] == "Run gitleaks" }.fetch("run")
      assert_includes script, GITLEAKS_SHA
      payload = "test archive fixture"
      script = script.sub(GITLEAKS_SHA, Digest::SHA256.hexdigest(payload))
      Dir.mktmpdir("proofgate-download-") do |dir|
        bin = File.join(dir, "bin")
        FileUtils.mkdir_p(bin)
        trace = File.join(dir, "trace")
        if %w[valid tampered].include?(download)
          File.write(File.join(dir, "gitleaks_8.30.1_linux_x64.tar.gz"), download == "valid" ? payload : payload + "corrupted")
        end
        {"curl" => download == "failed" ? "exit 7" : "exit 0",
         "tar" => 'echo extracted >> "$TRACE"',
         "gitleaks" => 'echo executed >> "$TRACE"'}.each do |name, body|
          path = File.join(bin, name)
          File.write(path, "#!/bin/sh\n#{body}\n")
          File.chmod(0755, path)
        end
        out, err, result = Open3.capture3({"PATH" => "#{bin}:#{ENV['PATH']}", "TRACE" => trace},
          "bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script, chdir: dir)
        if download == "valid"
          assert result.success?, out + err
          assert_equal %w[extracted executed], File.readlines(trace).map(&:strip)
        else
          refute result.success?, out + err
          refute File.exist?(trace), "unverified archive reached extraction or execution"
        end
      end
    end
  end

  def test_failed_demo_does_not_signal_the_calling_process_group
    Dir.mktmpdir("proofgate-demo-") do |dir|
      ruby = File.join(dir, "ruby")
      File.write(ruby, "#!/bin/sh\nexit 42\n")
      File.chmod(0755, ruby)
      # Isolate this subprocess group: the regression must never signal the test runner.
      _, _, result = Open3.capture3({"PATH" => "#{dir}:#{ENV['PATH']}"},
        "bash", File.join(ROOT, "scripts/demo.sh"), pgroup: true)
      assert result.exited?, "demo terminated its process group after an early failure"
      assert_equal 42, result.exitstatus
    end
  end
end
