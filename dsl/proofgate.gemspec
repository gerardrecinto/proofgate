require_relative "lib/proofgate/version"

Gem::Specification.new do |s|
  s.name = "proofgate"
  s.version = Proofgate::VERSION
  s.summary = "Ruby DSL for Proofgate access policies"
  s.description = "Write access policies in Ruby and compile them to the IR the Proofgate prover checks."
  s.authors = ["Gerard Recinto"]
  s.license = "MIT"
  s.homepage = "https://github.com/gerardrecinto/proofgate"
  s.required_ruby_version = ">= 2.6"
  s.files = Dir["lib/**/*.rb", "bin/*"]
  s.bindir = "bin"
  s.executables = ["proofgate-rb"]
end
