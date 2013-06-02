# DESCRIPTION: is part of the flowtag toolkit and provides a Tk widget for visualizing and selecting flows on a canvas
# FLOWTAG - parses and visualizes pcap data
# Copyright (C) 2007 Christopher Lee
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

require 'date'
require 'tk/parallelcoordinates'

module FlowTag
	class FlowCanvas
		def cb_select(tuples)
			@selected_flows = []
			tuples.each do |t|
				key = t.join("|")
				@selected_flows += @flow_keys[key]
			end
			@select_cb.call @selected_flows if @select_cb
		end

		def select_flow(sip,dip,sp,dp)
			@pcp.set_tuple_state(@cflow,Tk::ParallelCoordinates::STATE_NORMAL) if @cflow
			key = dp.to_s+"|"+sip
			@cflow = key
			@pcp.set_tuple_state(key,Tk::ParallelCoordinates::STATE_CURRENT)
		end

		def set_select_cb(callback)
			@select_cb = callback
		end

		def set_time_range(low, high)
			@time_low = low
			@time_high = high
			filter
		end

		def set_byte_range(low, high)
			@byte_low = low
			@byte_high = high
			filter
		end

		def set_packet_range(low, high)
			@pkt_low = low
			@pkt_high = high
			filter
		end

		def filter
			@flow_keys.each do |key,flows|
				flows.each do |fl|
					if fl[FlowDB::PKTS] < @pkt_low or fl[FlowDB::PKTS] > @pkt_high or 
						fl[FlowDB::BYTES] < @byte_low or fl[FlowDB::BYTES] > @byte_high or 
						fl[FlowDB::ST] < @time_low or fl[FlowDB::ST] > @time_high
						@pcp.set_tuple_state(key,Tk::ParallelCoordinates::STATE_FILTERED)
					else
						@pcp.set_tuple_state(key,Tk::ParallelCoordinates::STATE_NORMAL)
					end
				end
			end
		end

		def pack(*args)
			@pcp.pack(*args)
		end

		def initialize(parent, flows)
			hostseen = {}
			hosts = []
			@selected_flows = @flows = flows
			flows.each do |k,fl|
				sip = fl[FlowDB::SIP]
				next if hostseen[sip]
				hosts.push(sip)
				hostseen[sip]=1
			end
			model = [ 
				{ 
					:name => 'Port',
					:type => 'range',
					:scale => '3rt',
					:min => 0,
					:max => 65535,
					:ofmt => '%d',
					#:items => [1,22,80,137,443,1024,5900,6667,31337,65335]
				},
				{
					:name => 'Host',
					:type => 'list',
					:list => hosts
				}
			]
			@pcp = Tk::ParallelCoordinates.new(parent, 500, 360, model)
			@pcp.field_separator = "|"
			@pcp.set_select_cb( proc { |tuples| cb_select(tuples) } )
			@flow_keys = {}
			@pkt_low = @byte_low = @pkt_high = @byte_high = @time_high = 0
			@time_low = 2**32
			flows.each do |k,fl|
				key = fl[FlowDB::DP].to_s+"|"+fl[FlowDB::SIP]
				skip = (@flow_keys[key]) ? true:false
				@flow_keys[key] = [] unless @flow_keys[key]
				@flow_keys[key].push(fl)
				@pkt_high = fl[FlowDB::PKTS] if fl[FlowDB::PKTS] > @pkt_high
				@byte_high = fl[FlowDB::BYTES] if fl[FlowDB::BYTES] > @byte_high
				@time_low = fl[FlowDB::ST] if fl[FlowDB::ST] < @time_low
				@time_high = fl[FlowDB::ST] if fl[FlowDB::ST] > @time_high
				next if skip
				@pcp.addtuple([fl[FlowDB::DP],fl[FlowDB::SIP]])
			end
		end
	end
end