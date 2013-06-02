unless Kernel.respond_to?(:require_relative)
  module Kernel
    def require_relative(path)
      require File.join(File.dirname(caller[0]), path.to_str)
    end
  end
end

require_relative 'helper'

class TestFlowtag < Test::Unit::TestCase	
	#should "create a flowdb from the test.pcap and dump the flows" do
	def test_create_flowdb
		File.unlink('test/test.pcap.flows') if File.exists?('test/test.pcap.flows')
		File.unlink('test/test.pcap.pkts') if File.exists?('test/test.pcap.pkts')
		File.unlink('test/test.pcap.tags') if File.exists?('test/test.pcap.tags')
		fdb = FlowTag::FlowDB.new('test/test.pcap')
		assert(File.exists?('test/test.pcap.flows'))
		assert(File.exists?('test/test.pcap.pkts'))
		assert(File.exists?('test/test.pcap.tags'))
		fdb.dumpflows
	end
	
	#should "get the first pktid of the test.pcap" do
	def test_get_first_pktid
		flow = ['192.168.44.100', '72.14.207.99', 50697, 80]
		fdb = FlowTag::FlowDB.new('test/test.pcap')
		pid = fdb.getfirstpktid(*flow)
		assert_equal(0,pid)
	end
	
	#should "return no tags for the first flow" do
	def test_return_no_tags_for_first_flow
		flow = ['192.168.44.100', '72.14.207.99', 50697, 80]
		fdb = FlowTag::FlowDB.new('test/test.pcap')
		tags = fdb.getflowtags(flow)
		assert_equal(0,tags.length)
	end
	
	#should "get all flows tagged with test should be empty" do
	def test_get_all_flows_tagged_with_test_should_be_empty
		fdb = FlowTag::FlowDB.new('test/test.pcap')
		flows = fdb.flows_taggedwith("test")
		assert_equal(0,flows.length)
	end
	
	#should "tag the first flow with test and retrieve it" do
	def test_tag_the_first_flow_with_test_and_retrieve_it
		flow = ['192.168.44.100', '72.14.207.99', 50697, 80]
		fdb = FlowTag::FlowDB.new('test/test.pcap')
		fdb.tag_flow(flow,["test"])
		flows = fdb.flows_taggedwith("test")
		assert_equal(1,flows.length)
	end
	
	#should "write the tags database and reload" do
	def test_write_tags_database_and_reload
		flow = ['192.168.44.100', '72.14.207.99', 50697, 80]
		fdb = FlowTag::FlowDB.new('test/test.pcap')
		fdb.tag_flow(flow,["test"])
		fdb.writetagdb
		fdb = FlowTag::FlowDB.new('test/test.pcap')
		flows = fdb.flows_taggedwith("test")
		assert_equal(1, flows.length)
		fdb.tag_flow(flow,[])
		fdb.writetagdb
		fdb = FlowTag::FlowDB.new('test/test.pcap')
		flows = fdb.flows_taggedwith("test")
		assert_equal(0, flows.length)
	end
	
	#should "list all the tags and receive one, test" do
	def test_list_all_tags_and_receive_test
		flow = ['192.168.44.100', '72.14.207.99', 50697, 80]
		fdb = FlowTag::FlowDB.new('test/test.pcap')
		fdb.tag_flow(flow,["test"])
		tags = fdb.tags
		assert_equal(1, tags.length)
		assert_equal("test", tags[0])
	end
end
