require "json"
require "proofgate/version"
require "proofgate/builder"

# Author access policies in Ruby, compile them to the JSON IR that the Rust prover and
# the Go gateway consume.
module Proofgate
  class Error < StandardError; end

  # Evaluate a policy file. Errors point at the line in the file that caused them.
  def self.load_file(path)
    source = File.read(path)
    builder = Builder.new(File.basename(path, ".rb"), path)
    builder.instance_eval(source, path, 1)
    builder
  end

  def self.define(name, &block)
    builder = Builder.new(name, nil)
    builder.instance_eval(&block)
    builder
  end

  def self.compile_file(path)
    JSON.pretty_generate(load_file(path).to_ir) + "\n"
  end
end
