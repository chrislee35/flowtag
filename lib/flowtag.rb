unless Kernel.respond_to?(:require_relative)
  module Kernel
    def require_relative(path)
      require File.join(File.dirname(caller[0]), path.to_str)
    end
  end
end

require_relative 'flowtag/version'
require_relative 'flowtag/flowcanvas'
require_relative 'flowtag/flowdb'
require_relative 'flowtag/flowtable'
require_relative 'flowtag/pcapparser'
