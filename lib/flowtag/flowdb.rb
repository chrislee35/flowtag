# DESCRIPTION: is part of the flowtag toolkit and wraps a flowdb
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

require 'flowtag/pcapparser'
require 'ipaddr'

module FlowTag
	class FlowDB
		ST = 0
		SIP = 1
		DIP = 2
		SP = 3
		DP = 4
		PKTS = 5
		BYTES = 6
		FIRST_PKT = 7
		TAGS = 8

		attr_reader :flows, :tags_flows
		def initialize(pcapfile,basedir=nil)
			@pcapfile = pcapfile
			basedir = File.dirname(pcapfile) unless basedir
			basename = basedir+"/"+File.basename(pcapfile)
			raise "Cannot find pcapfile, #{pcapfile}" unless File.exists?(pcapfile)
			@pcapfh = File.new(pcapfile, 'rb')
			unless File.exists?(basename+".flows") and File.exists?(basename+'.pkts') and File.exists?(basename+'.tags')
				# the flow and packet database are missing, let's generate them
				flowdb = File.new(basename+".flows", 'wb')
				pktdb = File.new(basename+".pkts", 'wb')
				tagdb = File.new(basename+".tags", 'w')
				create_flowdb(basename, flowdb, pktdb)
				flowdb.close
				pktdb.close
				tagdb.close
				@flowdb = File.new(basename+".flows", 'rb')
				@pktdb = File.new(basename+".pkts", 'rb')
				@tagdb = File.new(basename+".tags", 'r')
				@flows = readflows
				@tags_flows = {}
				@flows_tags = {}
			else
				@flowdb = File.new(basename+".flows", 'rb')
				@pktdb = File.new(basename+".pkts", 'rb')
				@tagdb = File.new(basename+".tags", 'r')
				@flows = readflows
				# readtags must be called AFTER readflows
				@tags_flows, @flows_tags = readtags
			end
			@tags_updated = false
		end

		def close
			@pcapfh.close if @pcapfh
			@pktdb.close if @pktdb
			@flowdb.close if @flowdb
			@tagdb.close if @tagdb
		end

		def create_flowdb(pcapfile, flowdb, pktdb)
			offset = 24 # offset into the pcap file, starts at 24 to skip header
			pktid = 0   # database id of the pkt, increments for each matching packet
			flows = {}  # flow hash to store and check for keys
			pkts = []   # stores the packet database
			pcap = PcapParser.new(File.new(pcapfile,'rb'))
			pcap.each do |pkt|
				unless pkt.tcp?
					offset += 16 + pkt.length
					next
				end
				tuple = [pkt.ip_src, pkt.tcp_sport, pkt.tcp_dport, pkt.ip_dst]
				key = tuple.join "|"
				rkey = tuple.reverse.join "|"
				if flows[rkey]
					key = rkey
				end
				if flows[key]
					last_pkt_id = flows[key][:last_pkt]
					pkts[last_pkt_id][:next_pkt] = pktid
					flows[key][:last_pkt] = pktid
				else
					flows[key] = { :st => pkt.time, :sip => pkt.ip_src, :dip => pkt.ip_dst, :sp => pkt.tcp_sport, :dp => pkt.tcp_dport, :pkts => 0, :bytes => 0 }
					flows[key][:first_pkt] = flows[key][:last_pkt] = pktid
				end
				flows[key][:pkts] += 1
				flows[key][:bytes] += pkt.length
				pkts[pktid] = { :offset => offset, :next_pkt => 0 }
				offset += 16 + pkt.length
				pktid+=1
			end
			pcap.close

			# write out the flow database and the packet database
			flows.sort_by{|key,flow| flow[:st]}.each do |key,flow|
				flowdb.write( [ flow[:st], flow[:sip], flow[:dip], flow[:sp], flow[:dp], flow[:pkts], flow[:bytes], flow[:first_pkt] ].pack("NNNnnNNn") )
				flows[key] = [flow[:st], [flow[:sip]].pack("N").unpack("C4").join("."), [flow[:dip]].pack("N").unpack("C4").join("."), flow[:sp], flow[:dp], flow[:pkts], flow[:bytes], flow[:first_pkt], []]
			end
			pkts.each do |pkt|
				pktdb.write([pkt[:offset],pkt[:next_pkt]].pack("Nn"))
			end
			return flows
		end

		def dumpflows
			@flows.sort_by { |k,f| f[ST].to_i }.each do |key,flow|
				puts flow.join(" ")
			end
		end

		def readflows
			flows = {}
			@flowdb.seek(0)
			while ! @flowdb.eof?
				(st,sip,dip,sp,dp,pkts,bytes,first_pkt) = @flowdb.read(26).unpack("NNNnnNNn")
				sip = IPAddr.ntop([sip].pack("N"))
				dip = IPAddr.ntop([dip].pack("N"))
				key = [sip,dip,sp,dp].join("|")
				flows[key] = [st,sip,dip,sp,dp,pkts,bytes,first_pkt,[]]
			end
			flows
		end

		def getflows
			return @flows
		end

		def readtags
			@tagdb.seek 0
			flows_tags = {}
			tags_flows = {}
			@tagdb.each_line do |l|
				(sip,dip,sp,dp,*tags)=l.strip.split(/\|/)
				key = [sip,dip,sp,dp].join("|")
				flows_tags[key] = tags
				@flows[key][TAGS] = tags
				tags.each do |tag|
					tags_flows[tag] = [] unless tags_flows[tag]
					tags_flows[tag].push(key)
				end 
			end
			[tags_flows, flows_tags]
		end

		def writetagdb
			return true unless @tags_updated
			@tagdb.close if @tagdb
			tagdb = File.new(@pcapfile+'.tags', 'w')
			@flows_tags.each do |key,tags|
				tagdb.puts key+"|"+tags.join("|")
			end
			tagdb.close
			@tagdb = File.new(@pcapfile+'.tags', 'r')
			@tags_updated = false
			true
		end

		def tag_flow(flow, tags)
			@tags_updated = true
			tags.uniq!
			key = flow.join("|")
			if @flows_tags[key]
				currtags = @flows_tags[key]
				currtags.each do |tag|
					@tags_flows[tag].delete(key)
					@tags_flows.delete(tag) if @tags_flows[tag].length == 0
				end
			end
			@flows_tags[key] = tags
			@flows[key][TAGS] = tags
			tags.each do |tag|
				@tags_flows[tag] = [] unless @tags_flows[tag]
				@tags_flows[tag].push(key)
			end
		end

		def getflowtags(flow)
			key = flow.join("|")
			@flows_tags[key] || []
		end

		def flows_taggedwith(tag)
			keys = @tags_flows[tag]
			flows = []
			if keys
				keys.each do |key|
					flows.push(@flows[key])
				end
			end
			flows
		end

		def tags
			@tags_flows.keys
		end

		def getfirstpktid(sip, dip, sp, dp)
			@flows.each do |key,flow|
				if flow[SIP] == sip and flow[DIP] == dip and flow[SP] == sp and flow[DP] == dp
					return flow[FIRST_PKT]
				end
			end
			-1
		end

		def getpktrec(pktid)
			offset = 6*pktid
			@pktdb.seek(offset)
			(poff, pktid) = @pktdb.read(6).unpack("Nn")
			[poff, pktid] 
		end

		def getdata(offset)
			@pcapfh.seek(offset)
			# this needs to be endian sensitive...
			if @endian
				(tv_sec, tv_usec, caplen, origlen) = @pcapfh.read(16).unpack(@endian)
			else
				(tv_sec, tv_usec, caplen, origlen) = @pcapfh.read(16).unpack("VVVV")
				@endian = "VVVV"
				if caplen > 5000
					@pcapfh.seek(offset)
					(tv_sec, tv_usec, caplen, origlen) = @pcapfh.read(16).unpack("NNNN")
					@endian = "NNNN"
				end
			end
			pkt = @pcapfh.read(caplen)
			type = (pkt[12,2].unpack("n"))[0]
			return nil unless type == 0x0800
			return nil unless pkt[14] == 0x45
			return nil unless pkt[14+10-1] == 0x06
			tcp_header_len = (pkt[14+20+12]>>4)<<2
			pkt[14+20+tcp_header_len,1000] || ''
		end

		def getflowdata_frompkt(first_pkt, limit=nil)
			(poff,npkt) = fp_rec = getpktrec(first_pkt)
			payload = getdata(poff)
			while npkt != 0
				(poff,npkt) = getpktrec(npkt)
				data = getdata(poff)
				payload += data if data
				break if limit and payload.length > limit
			end
			payload
		end

		def getflowdata(sip, dip, sp, dp, limit=nil)
			first_pkt = getfirstpktid(sip, dip, sp, dp)
			return '' if first_pkt == -1
			return getflowdata_frompkt(first_pkt, limit)
		end
	end
end
