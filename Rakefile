# encoding: utf-8

require 'rubygems'
require 'bundler'
begin
	Bundler.setup(:default, :development)
rescue Bundler::BundlerError => e
	$stderr.puts e.message
	$stderr.puts "Run `bundle install` to install missing gems"
	exit e.status_code
end
require 'rake'

require 'jeweler'
Jeweler::Tasks.new do |gem|
	# gem is a Gem::Specification... see http://docs.rubygems.org/read/chapter/20 for more options
	gem.name = "flowtag"
	gem.homepage = "https://rubygems.org/gems/flowtag"
	gem.license = "MIT"
	gem.summary = %Q{FlowTag visualizes pcap files for forensic analysis}
	gem.description = %Q{presents the user with a GUI interface to visualize and explore flows found from a given pcap file}
	gem.email = "rubygems@chrislee.dhs.org"
	gem.authors = ["Chris Lee"]
	gem.signing_key = "#{File.dirname(__FILE__)}/../gem-private_key.pem"
	gem.cert_chain  = ["#{File.dirname(__FILE__)}/../gem-public_cert.pem"]
	gem.files = FileList["{bin,lib}/**/*"].to_a
	gem.add_runtime_dependency "tk-double-slider", ">= 0.1.0"
	gem.add_runtime_dependency "tk-parallel-coordinates", ">= 0.1.0"
	gem.executables = ["flowtag","ftlistflows","ftpcap2flowdb","ftprintflow"]
end
Jeweler::RubygemsDotOrgTasks.new

require 'rake/testtask'
Rake::TestTask.new(:test) do |test|
	test.libs << 'lib' << 'test'
	test.pattern = 'test/**/test_*.rb'
	test.verbose = true
end


task :default => :test

require 'rdoc/task'
Rake::RDocTask.new do |rdoc|
	version = File.exist?('VERSION') ? File.read('VERSION') : ""

	rdoc.rdoc_dir = 'rdoc'
	rdoc.title = "rubot #{version}"
	rdoc.rdoc_files.include('README*')
	rdoc.rdoc_files.include('lib/**/*.rb')
end
