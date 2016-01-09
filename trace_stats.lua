-- from https://www.caida.org/~emile/data_proc/trace_stats.lua
--
--------------------------------------------------
-- $Header: /cvs/WIP/datcat-import/crawdad/bin/analysis/trace_stats.lua,v 1.1 2007/04/25 15:18:28 emile Exp $
-- extracts various stats (subset of crl_stats)
-- from a trace file, use like:
-- tshark -q <other opts> -Xlua_script:trace_stats.lua <trace>
-- wireshark/tshark needs to be compiled --with-lua
--------------------------------------------------

do
    ip_addr_extractor = Field.new("ip.addr")
    tcp_src_port_extractor = Field.new("tcp.srcport")
    tcp_dst_port_extractor = Field.new("tcp.dstport")
    udp_port_extractor = Field.new("udp.port")
    icmp_type_extractor = Field.new("icmp.type")
    icmp_code_extractor = Field.new("icmp.code")

    local function init_listener()
        local tap = Listener.new("frame")

----------------------
----- stats  functions
----------------------

-- tcp port counts
        local ipv4_tcp_src_cache = {}
        local ipv4_tcp_dst_cache = {}
        local ipv4_tcp_src_count = 0
        local ipv4_tcp_dst_count = 0
        function stats_ipv4_tcp_port_counts()
            local tcp_src_port
            local tcp_dst_port
            tcp_src_port = tcp_src_port_extractor()
            tcp_dst_port = tcp_dst_port_extractor()
            if ( tcp_src_port ) then
                if (not ipv4_tcp_src_cache[ tostring( tcp_src_port ) ] == true ) then
                    ipv4_tcp_src_cache[ tostring(  tcp_src_port ) ] = true
                    ipv4_tcp_src_count = ipv4_tcp_src_count + 1
                else
                    -- print("tcp_src_port already recorded")
                end
            else
                -- print("no tcp_src_port")
            end
            if ( tcp_dst_port ) then
                if (not ipv4_tcp_dst_cache[ tostring( tcp_dst_port ) ] == true ) then
                    ipv4_tcp_dst_cache[ tostring(  tcp_dst_port ) ] = true
                    ipv4_tcp_dst_count = ipv4_tcp_dst_count + 1
                    -- print("tcp_dst_port new: " .. tostring(tcp_dst_port) )
                else
                    -- print("tcp_dst_port old: " .. tostring(tcp_dst_port) )
                end
            else
                -- print("tcp_dst_port none: " .. tostring(tcp_dst_port) )
            end

        end

-- udp port counts
        local ipv4_udp_src_cache = {}
        local ipv4_udp_dst_cache = {}
        local ipv4_udp_src_count = 0
        local ipv4_udp_dst_count = 0
        function stats_ipv4_udp_port_counts()
            local udp_src_port
            local udp_dst_port
            udp_src_port, udp_dst_port = udp_port_extractor()
            if ( udp_src_port ) then
                if (not ipv4_udp_src_cache[ tostring( udp_src_port ) ] == true ) then
                    ipv4_udp_src_cache[ tostring(  udp_src_port ) ] = true
                    ipv4_udp_src_count = ipv4_udp_src_count + 1
                else
                    -- print("udp_src_port already recorded")
                end
            else
                -- print("no udp_src_port")
            end
            if ( udp_dst_port ) then
                if (not ipv4_udp_dst_cache[ tostring( udp_dst_port ) ] == true ) then
                    ipv4_udp_dst_cache[ tostring(  udp_dst_port ) ] = true
                    ipv4_udp_dst_count = ipv4_udp_dst_count + 1
                    -- print("udp_dst_port new: " .. tostring(udp_dst_port) )
                else
                    -- print("udp_dst_port old: " .. tostring(udp_dst_port) )
                end
            else
                -- print("udp_dst_port none: " .. tostring(udp_dst_port) )
            end
        end


-- icmp type code counts
        local ipv4_icmp_type_cache = {}
        local ipv4_icmp_type_count = 0
        function stats_icmp_type_counts(pinfo,tvb)
            local icmp_type
            local icmp_code
            icmp_type = icmp_type_extractor()
            icmp_code = icmp_code_extractor()
            if( icmp_type and icmp_code ) then
                if(not ipv4_icmp_type_cache[ tostring( icmp_type ) .. '-' .. tostring( icmp_code ) ] == true ) then
                    ipv4_icmp_type_cache[ tostring( icmp_type ) .. '-' .. tostring( icmp_code ) ] = true
                    ipv4_icmp_type_count = ipv4_icmp_type_count + 1
                else
                      -- print("icmp type and code already recorded")
                end
            else
              -- print("no icmp type and code")
            end
        end

-- ipv4 counts
        local ipv4_src_cache = {}
        local ipv4_dst_cache = {}
        local ipv4_src_count = 0
        local ipv4_dst_count = 0
        function stats_ipv4_counts(pinfo,tvb)
            local ip_src
            local ip_dst
            ip_src, ip_dst = ip_addr_extractor()
            if ( ip_src ) then 
                if (not ipv4_src_cache[ tostring(ip_src) ] == true ) then
                    ipv4_src_cache[ tostring(ip_src) ] = true 
                    ipv4_src_count = ipv4_src_count + 1
                else
                    -- print("src already recorded")
                end
                --- try counting tcp/udp and icmp once for every ipv4 pkt
                if     ( pinfo.ipproto == 1 ) then
                    stats_icmp_type_counts(pinfo,tvb)
                elseif ( pinfo.ipproto == 6 ) then
                    stats_ipv4_tcp_port_counts()
                elseif ( pinfo.ipproto == 17 ) then 
                    stats_ipv4_udp_port_counts()
                end
            else 
                -- print("NO src") 
            end
            if ( ip_dst ) then 
                if (not ipv4_dst_cache[ tostring(ip_dst) ] == true ) then
                    ipv4_dst_cache[ tostring(ip_dst) ] = true 
                    ipv4_dst_count = ipv4_dst_count + 1
                else
                    -- print("dst already recorded")
                end
            else 
                -- print("NO dst") 
            end
        end

-- start/end times
        local start_time
        local end_time
        function stats_start_end_times(pinfo)
            if (not start_time) then
                start_time =  pinfo.abs_ts
                end_time  =  pinfo.abs_ts
            else
                if ( start_time > pinfo.abs_ts ) then start_time = pinfo.abs_ts end
                if ( end_time < pinfo.abs_ts  ) then end_time = pinfo.abs_ts end
            end
        end

-------------------
----- tap functions
-------------------
        function tap.reset()
        end

        function tap.packet(pinfo,tvb,ip)
            stats_ipv4_counts(pinfo,tvb)
            stats_start_end_times(pinfo)
        end

        function tap.draw()
            print("=== extra stats ===================================================")
            print("start_time: " .. start_time )
            print("end_time: " .. end_time )
            print("ipv4_src_address_count: " .. ipv4_src_count ) 
            print("ipv4_dst_address_count: " .. ipv4_dst_count )
            print("ipv4_tcp_src_port_count: " .. ipv4_tcp_src_count ) 
            print("ipv4_tcp_dst_port_count: " .. ipv4_tcp_dst_count )
            print("ipv4_udp_src_port_count: " .. ipv4_udp_src_count ) 
            print("ipv4_udp_dst_port_count: " .. ipv4_udp_dst_count )
            print("ipv4_icmp_type_code_count: " .. ipv4_icmp_type_count )
            print("===================================================================")
        end
    end

    init_listener()
end
