do
    packets = 0;
    local function init_listener()
        local tap = Listener.new("frame","ip.addr == 10.0.0.0/8")
        function tap.reset()
            packets = 0;
        end
        function tap.packet(pinfo,tvb,ip)
            packets = packets + 1
        end
        function tap.draw()
            print("Packets to/from 10.0.0./8",packets)
        end
    end
    init_listener()
end
