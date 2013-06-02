# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'flowtag/version'

Gem::Specification.new do |spec|
	spec.name          = "flowtag"
  spec.version       = Flowtag::VERSION
	spec.homepage      = "https://rubygems.org/gems/flowtag"
	spec.license       = "MIT"
	spec.summary       = %q{FlowTag visualizes pcap files for forensic analysis}
	spec.description   = %q{presents the user with a GUI interface to visualize and explore flows found from a given pcap file}
	spec.email         = ["rubygems@chrislee.dhs.org"]
	spec.authors       = ["chrislee35"]
	spec.executables   = ["flowtag","ftlistflows","ftpcap2flowdb","ftprintflow"]

	spec.add_runtime_dependency "tk-doubleslider", ">= 0.1.1"
	spec.add_runtime_dependency "tk-parallelcoordinates", ">= 0.1.1"

	spec.add_development_dependency "bundler", "~> 1.3"
	spec.add_development_dependency "rake"

	spec.signing_key   = "#{File.dirname(__FILE__)}/../gem-private_key.pem"
	spec.cert_chain    = ["#{File.dirname(__FILE__)}/../gem-public_cert.pem"]

	spec.require_paths = ["lib"]
	spec.files         = `git ls-files`.split($/)
	spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
	spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
end
