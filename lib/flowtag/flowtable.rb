# DESCRIPTION: is part of the flowtag toolkit and provides a TK widget for listing the flows
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

require 'flowtag/flowdb'

module FlowTag
	class FlowTable
		@@column_lengths = [8,15,15,5,5,6,8,20]
		@@column_names = ['Time', 'Source IP', 'Dest. IP', 'SPort', 'DPort', 'Pkts', 'Bytes', 'Tags']

		def addflow(flow)
			entry = Time.at(flow[FlowDB::ST]).strftime("%H:%M:%S")+" "
			(1..@@column_lengths.length-2).each do |i|
				entry += flow[i].to_s.rjust(@@column_lengths[i])+" "
			end
			entry += flow[FlowDB::TAGS].join(" ")[0,20]
			@scrollbox.insert 'end', entry
		end

		def addflows(flows)
			flows.each do |flow|
				addflow(flow)
			end
		end

		def update_flow(idx, flow)
			entry = Time.at(flow[FlowDB::ST]).strftime("%H:%M:%S")+" "
			(1..@@column_lengths.length-2).each do |i|
				entry += flow[i].to_s.rjust(@@column_lengths[i])+" "
			end
			entry += flow[FlowDB::TAGS].join(" ")[0,20]
			@scrollbox.delete idx
			@scrollbox.insert idx, entry
		end


		def clear
			@scrollbox.clear
		end

		def pack(*args)
			@tableframe.pack(*args)
		end

		def unpack
			@tableframe.unpack
		end

		def selected
			items = []
			indices = @scrollbox.curselection
			indices.each do |i|
				items.push(@scrollbox.get(i))
			end
			if @select_cb
				@select_cb.call indices, items
			end
			@scrollbox.focus
		end

		def set_select_cb(callback)
			@select_cb = callback
		end

		def initialize(parent, flows)
			@rows = 0
			@tableframe = TkFrame.new(parent)
			header = ''
			(0..@@column_names.length-1).each do |i|
				header +=  @@column_names[i].center(@@column_lengths[i])+"|"
			end
			@table_header = TkLabel.new(@tableframe) {
				text header
				font TkFont.new('Monaco 12 bold')
				anchor 'sw'
				height 1
				padx 0
				pady 0
				foreground 'lightblue'
			}
			@scrollbox = scrollbox = TkScrollbox.new(@tableframe) {
				setgrid 'yes'
				takefocus 'yes'
				width 59
				font TkFont.new('Monaco 12')
			}
			@table_header.pack(:side=>'top',:fill=>'x')
			scrollbox.pack(:side=>'top',:fill=>'both',:expand=>1)
			scrollbox.bind('<ListboxSelect>', proc { |x| selected() })
			addflows(flows)
		end
	end
end