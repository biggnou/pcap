-- as of https://www.ibm.com/developerworks/community/blogs/kevgrig/entry/wireshark_lua_script_to_search_for_tcp_delays?lang=en
--
-- Usage: tshark -q -r ${CAPTURE_FILE} -X lua_script:tcpanomalies.lua
-- 
-- tcpanomalies.lua: Find all TCP tcpanomalies and:
--  1) Print the time it takes for a response to a SYN (either direction). Modify minSynResponseDelta in script to only print those longer than X seconds,
--  2) Print an ERROR if the response to a SYN is not SYNACK (e.g. RST),
--  3) Print an ERROR if a SYN is sent on the same stream without a response to a previous SYN,
--  4) Print a WARNING if a SYN does not receive a response by the end of the capture (only warning because capture may have ended right before a legitimate response).
-- Notes:
--  1) We look at each 4-tuple of (source IP, source port, destination IP, destination port) - Wireshark calls this a "stream" and conveniently numbers each tuple uniquely for us (tcp.stream),
--  2) By default, we suppress the warning if the script finds packets on a stream without a previous SYN as these are probably at the start of the capture for streams we didn't capture tcpanomalies for.
--  3) Only works on a single file, so use mergecap to merge rolling files together.
--
-- Example:
-- $ tshark -q -r http1-rstnoack.pcap -X lua_script:tcpanomalies.lua
-- tcpanomalies.lua: Started
-- tcpanomalies.lua: First packet time: "Mar 22, 2014 07:08:36.967090000 PDT"
-- tcpanomalies.lua: ===================================
-- tcpanomalies.lua: ERROR: Received RST in response to SYN after 2.4080276489258e-05 seconds. First SYN sent: "Mar 22, 2014 07:08:36.967090000 PDT", Stream 0, Frame: 1, Source: nil:36016, Destination: nil:80, Current frame time: "Mar 22, 2014 07:08:36.967114000 PDT" (Frame: 2)
-- tcpanomalies.lua: WARNING: Stream 1 did not get a response by the end of the capture. First SYN sent: "Mar 22, 2014 07:08:36.967251000 PDT", Stream 1, Frame: 3, Source: 127.0.0.1:45317, Destination: 127.0.0.1:80, Current frame time:  (Frame: )
-- tcpanomalies.lua: ===================================
-- tcpanomalies.lua: Last packet time: "Mar 22, 2014 07:08:36.967251000 PDT"
-- tcpanomalies.lua: Finished

local suppressMissingHandshake = true

-- Update this to search for long SYN response times. In seconds, e.g. .0000250
local minSynResponseDelta = 1

-- Update this to search for gaps between packets after the handshake. In seconds, e.g. .0000250
local minDiffDelta = 0

-- Internal variable
local lastTime = nil

do
  function scriptprint(message)
    print("tcpanomalies.lua: " .. message)
  end

  scriptprint("Started tcpanomalies.lua")

  -- frame
  local frame_time = Field.new("frame.time")
  local frame_number = Field.new("frame.number")
  local frame_len = Field.new("frame.len")
  local frame_epochtime = Field.new("frame.time_epoch")

  -- tcp
  local tcp_dstport = Field.new("tcp.dstport")
  local tcp_srcport = Field.new("tcp.srcport")
  local tcp_stream = Field.new("tcp.stream")
  local tcp_pdu_size = Field.new("tcp.pdu.size")
  local tcp_flags_syn = Field.new("tcp.flags.syn")
  local tcp_flags_ack = Field.new("tcp.flags.ack")
  local tcp_flags_rst = Field.new("tcp.flags.reset")
  local tcp_flags_fin = Field.new("tcp.flags.fin")

  -- ipv4
  local ip_dst = Field.new("ip.dst")
  local ip_src = Field.new("ip.src")

  local streams = {}

  local function init_listener()
    local tap = Listener.new("tcp")
    function tap.reset()
      -- print("tap reset")
    end

    function tap.packet(pinfo,tvb)
      local dstport = tcp_dstport()
      local srcport = tcp_srcport()
      local frametime = tostring(frame_time())
      local frameepochtime = tonumber(tostring(frame_epochtime()))
      local framenumber = tonumber(tostring(frame_number()))
      local ipdst = ip_dst()
      local ipsrc = ip_src()
      local stream = tonumber(tostring(tcp_stream()))
      local flagssyn = tonumber(tostring(tcp_flags_syn()))
      local flagsack = tonumber(tostring(tcp_flags_ack()))
      local flagsrst = tonumber(tostring(tcp_flags_rst()))
      local flagsfin = tonumber(tostring(tcp_flags_fin()))

      if lastTime == nil then
        scriptprint("First packet time: " .. frametime)
        scriptprint("===================================")
      end
      lastTime = frametime

      -- First check if this is a new connection: SYN and not ACK
      if flagssyn == 1 and flagsack == 0 then

        -- Check if there's any previous machine state
        if machine ~= nil then
          if machine.state == 1 then
            scripterror(stream, machine, "Never received SYN response before a new SYN", frametime, framenumber)
          end
        end

        streams[stream] = {
          frame = framenumber,
          time = frametime,
          source = tostring(ipsrc) .. ":" .. tostring(srcport),
          destination = tostring(ipdst) .. ":" .. tostring(dstport),
          start = frameepochtime,
          state = 1,
          lastpackettime = frameepochtime,
          lastpacketframe = framenumber,
          lastpacketdatetime = frametime
        };
      else
        -- Otherwise, use the state machine

        local machine = streams[stream]

        if machine ~= nil then
          if machine.state == 1 then
            -- Only have a SYN so far, so we expect this to be a SYN ACK
            local diff = frameepochtime - machine.start
            if flagsack == 1 and flagssyn == 1 then
              if diff >= minSynResponseDelta then
                postsyn(stream, machine, "SYNACK", frametime, framenumber, diff)
              end
              machine.state = 2
            elseif flagsrst == 1 then
              if diff >= minSynResponseDelta then
                scripterror(stream, machine, "Received RST in response to SYN after " .. diff .. " seconds", frametime, framenumber)
              end
              machine.state = 2
            elseif flagsfin == 1 then
              scriptwarning(stream, machine, "Received FIN in response to SYN after " .. diff .. " seconds", frametime, framenumber)
              machine.state = 2
            else
              scripterror(stream, machine, "Expected SYNACK or RST, instead got frame " .. framenumber .. " after " .. diff .. " seconds", frametime, framenumber)
              machine.state = 3
            end
          elseif machine.state == 3 then
            -- This state means that we've already reported an error on this stream, so we only report the first error
          else
            -- Check for delta between any other two packets
            local diff = frameepochtime - machine.lastpackettime

            if minDiffDelta > 0 and diff >= minDiffDelta then
              local passMachine = machine
              if machine.state == -1 then
                passMachine = nil
              end
              scriptwarning(stream, passMachine, "Time between frames " .. machine.lastpacketframe .. " (" .. machine.lastpacketdatetime .. ") and " .. framenumber .. " (" .. frametime .. ") is " .. diff .. " seconds.", frametime, framenumber)
            end

            machine.lastpackettime = frameepochtime
            machine.lastpacketframe = framenumber
            machine.lastpacketdatetime = frametime
          end
        else
          -- We haven't seen a handshake on this stream, but we track it anyway to find packet diffs
          streams[stream] = {
            state = -1,
            lastpackettime = frameepochtime,
            lastpacketframe = framenumber,
            lastpacketdatetime = frametime
          };
          if not suppressMissingHandshake then
            scriptwarning(stream, nil, "Frame " .. framenumber .. " did not have matching SYN", frametime, framenumber)
          end
        end
      end
    end
    
    function postsyn(stream, machine, response, responsetime, responseframe, diff)
      scriptprint("Stream " .. stream .. " received SYN response (" .. response .. ") after " .. diff .. " seconds. SYN sent: " .. machine.time .. " (Frame: " .. machine.frame .. "), Source: " .. machine.source .. ", Destination: " .. machine.destination .. ", Response time: " .. responsetime .. " (Frame: " .. responseframe .. ")")
    end
    
    function scripterror(stream, machine, message, curtime, curframe)
      scriptalert("ERROR", stream, machine, message, curtime, curframe)
    end
    
    function scriptwarning(stream, machine, message, curtime, curframe)
      scriptalert("WARNING", stream, machine, message, curtime, curframe)
    end
    
    function scriptalert(alert, stream, machine, message, curtime, curframe)
      if machine ~= nil then
        if curtime ~= nil then
          scriptprint(alert .. ": " .. message .. ". First SYN sent: " .. machine.time .. ", Stream " .. stream .. ", Frame: " .. machine.frame .. ", Source: " .. machine.source .. ", Destination: " .. machine.destination .. ", Current frame time: " .. curtime .. " (Frame: " .. curframe .. ")")
        else
          scriptprint(alert .. ": " .. message .. ". First SYN sent: " .. machine.time .. ", Stream " .. stream .. ", Frame: " .. machine.frame .. ", Source: " .. machine.source .. ", Destination: " .. machine.destination)
        end
      else
        if curtime ~= nil then
          scriptprint(alert .. ": " .. message .. ". Stream " .. stream .. ", Current frame time: " .. curtime .. " (Frame: " .. curframe .. ")")
        else
          scriptprint(alert .. ": " .. message .. ". Stream " .. stream)
        end
      end
    end

    function tap.draw()
      -- Check for any SYNs without a response
      for stream,machine in pairs(streams) do
        if machine.state == 1 then
          scriptwarning(stream, machine, "Stream " .. stream .. " did not get a response by the end of the capture", nil, nil)
        end
      end

      if lastTime ~= nil then
        scriptprint("===================================")
        scriptprint("Last packet time: " .. lastTime)
      end

      scriptprint("Finished")
    end
  end

  init_listener()
end
