require "minitest/autorun"
require "tmpdir"
$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "proofgate"

class BuilderTest < Minitest::Test
  EXAMPLES = File.expand_path("../../examples/deploys", __dir__)

  def build(&block)
    Proofgate.define("t", &block).to_ir
  end

  def test_emits_the_ir_the_prover_reads
    ir = build do
      dimension :env, %w[dev prod]
      dimension :role, %w[sre eng]
      allow :sre_prod, "SREs run prod", env: "prod", role: "sre"
      deny :nothing_else
      never :no_eng_prod, "Engineers stay out of prod", env: "prod", role: "eng"
      always :sre_always, role: "sre"
    end
    assert_equal 1, ir["version"]
    assert_equal [{ "name" => "env", "values" => %w[dev prod] }, { "name" => "role", "values" => %w[sre eng] }], ir["dimensions"]
    assert_equal({ "id" => "sre_prod", "description" => "SREs run prod", "when" => { "env" => ["prod"], "role" => ["sre"] }, "effect" => "allow" }, ir["rules"][0])
    assert_equal({}, ir["rules"][1]["when"])
    assert_equal %w[never_allow always_allow], ir["invariants"].map { |i| i["kind"] }
  end

  def test_non_string_values_are_stringified
    ir = build do
      dimension :approved, [true, false]
      allow :yes, approved: true
    end
    assert_equal %w[true false], ir["dimensions"][0]["values"]
    assert_equal ["true"], ir["rules"][0]["when"]["approved"]
  end

  def test_policy_name_overrides_the_default
    assert_equal "deploys", Proofgate.define("t") { policy_name "deploys"; dimension :a, %w[x] }.to_ir["name"]
  end

  def test_unknown_dimension_is_refused
    e = assert_raises(Proofgate::Error) { build { dimension :a, %w[x]; allow :r, b: "x" } }
    assert_match(/dimension 'b'/, e.message)
  end

  def test_unknown_value_lists_the_known_ones
    e = assert_raises(Proofgate::Error) { build { dimension :a, %w[x y]; allow :r, a: "z" } }
    assert_match(/'z'.*Known values: x, y/, e.message)
  end

  def test_duplicate_ids_across_rules_and_invariants
    assert_raises(Proofgate::Error) { build { dimension :a, %w[x]; allow :r; deny :r } }
    assert_raises(Proofgate::Error) { build { dimension :a, %w[x]; allow :r; never :r } }
  end

  def test_duplicate_dimension_and_empty_policy
    assert_raises(Proofgate::Error) { build { dimension :a, %w[x]; dimension :a, %w[y] } }
    assert_raises(Proofgate::Error) { build { allow :r } }
    assert_raises(Proofgate::Error) { build {} }
  end

  def test_errors_in_a_file_point_at_the_line
    Dir.mktmpdir do |dir|
      path = File.join(dir, "p.rb")
      File.write(path, "dimension :env, %w[dev]\n\nallow :r, env: \"prod\"\n")
      e = assert_raises(Proofgate::Error) { Proofgate.load_file(path) }
      assert_match(/p\.rb:3: /, e.message)
    end
  end

  def test_compiled_examples_are_up_to_date
    Dir[File.join(EXAMPLES, "*.rb")].each do |rb|
      json = File.join(EXAMPLES, File.basename(rb, ".rb") + ".json")
      assert_equal File.read(json), Proofgate.compile_file(rb), "#{json} is stale, run: make examples"
    end
  end

  def test_compiled_example_with_the_rust_prover
    bin = ENV["PROOFGATE_BIN"]
    skip "PROOFGATE_BIN not set" unless bin
    out = `#{bin} check #{File.join(EXAMPLES, "policy.json")} 2>&1`
    assert $?.success?, out
    assert_match(/PROVEN.*Contractors never change prod/, out)
    broken = `#{bin} check #{File.join(EXAMPLES, "policy_broken.json")} 2>&1`
    assert_equal 1, $?.exitstatus
    assert_match(/FAILS/, broken)
  end
end
