# Flowtag

FlowTag is an interactive network trace viewer. It operates on PCAP files, produces a database of flows, and then visualizes the results. The user can then filter for flows of interest, view the payload, and tag the flow with relevant keywords. The current version is written in Ruby using the Tk interface. The code is released under GPL, except the pcapparser library, which is released under LGPL.

<img src='http://chrislee.dhs.org/projects/flowtag/flowtag2.png' />

The interface is comprised of 6 main elements as follows:

* Flow Table. A list of matching flows (source IP, destination IP, source port, destination port, and time). When a flow in this table is clicked on, the contents of the flow will be displayed in the Payload View.
* Flow Tags. This small entry box allows the user to associate keywords (tags) with the currently selected flow.
* Payload View. When the user clicks on a flow in the Flow Table, the reconstructed payload of the currently selected flow is displayed in this text box.
* Connection Visualization. This canvas displays a parallel coordinate plot with the left axis mapping the TCP ports (using a cube root scaling to emphasize the lower ports) and the right axis mapping the IP addresses in order of appearance in the network trace file.
* Filters. Filters allow the user to remove uninteresting flows based on time, the number of packets in the flow, or the number of bytes in the flow. The time slider is a double-ended linear slider and the packets and bytes sliders are double-ended logarithmic sliders (to give lower numbers have more selection accuracy since they generally more important).
* Tags List. This selector lists all the defined tags and allows the user to filter for flow matching the selected tag.

The FlowTag package contains 3 command-line tools in addition to the GUI. These tools are provided to telp with simple automation and scripting. pcap2flowdb creates a flow database from a pcap file. The database can then be read by the listflows and printflow tools. The listflows tool lists all the flow tuples contained in the flow database. The printflow tool outputs the payload of a specified flow.

## Installation

For mac users, to install Ruby with Tk, please use something akin to the following:

	sudo port install ruby19+c_api_docs+doc+mactk

If you want to go the "RVM" route, which I don't recommend for new users, but I do recommend for anyone writing new modules.  You'll need to install TK and TCL libraries to make this work.
I'm guessing at this point, but probably:

	sudo port install tk+quartz

Then, go ahead and install all three Rubies as follows:

	rvm reinstall 1.8.7 --enable-shared --enable-pthread --with-tk --with-tcl
	rvm reinstall 1.9.3 --enable-shared --enable-pthread --with-tk --with-tcl
	rvm reinstall 2.0.0 --enable-shared --enable-pthread --with-tk --with-tcl

Add this line to your application's Gemfile:

    gem 'flowtag'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install flowtag

## Usage

	flowtag test.pcap

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
