--[[
    A tap that displays IPv4 subnet statistics in a GUI menu.
    Copyright (C) 2020 Christopher Maynard

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
--]]
-------------------------------------------------------------------------

local tap_subnets_info =
{
    version = "1.3",
    author = "Christopher Maynard",
    description = "A tap that displays IPv4 subnet statistics in a GUI menu",
}

set_plugin_info(tap_subnets_info)

if not gui_enabled() then
    return
end

local ip_src = Field.new("ip.src")
local ip_dst = Field.new("ip.dst")
local frame_len = Field.new("frame.len")

-- Number of instances of the tap created so far
local instances = 0

local settings = {
    subnet_bits = 0 -- Range: 1-32 or 0 for Classful subnets
}

local subnet_mask = {
    0x80000000, 0xc0000000, 0xe0000000, 0xf0000000,
    0xf8000000, 0xfc000000, 0xfe000000, 0xff000000,
    0xff800000, 0xffc00000, 0xffe00000, 0xfff00000,
    0xfff80000, 0xfffc0000, 0xfffe0000, 0xffff0000,
    0xffff8000, 0xffffc000, 0xffffe000, 0xfffff000,
    0xfffff800, 0xfffffc00, 0xfffffe00, 0xffffff00,
    0xffffff80, 0xffffffc0, 0xffffffe0, 0xfffffff0,
    0xfffffff8, 0xfffffffc, 0xfffffffe, 0xffffffff
}

function subnets_statistics_window()

    instances = instances + 1

    --[[
        The tap data, locally accessible by every function of the tap
        beware not to use a global for taps with multiple instances or you might
        find it has been written by more instances of the tap, which is not what
        we want.  Each tap will have its own private instance of tapdata.
    --]]
    local tapdata = {
        ip = {}
    }

    local taptext = {
        ip = ""
    }

    -- Declare the window we will use
    -- TODO: Too bad we can't add the capture file name to the title ... yet?
    --       Too bad we can't add the display filter to the title ... yet?
    local tapwin = TextWindow.new(
        "Subnets Statistics (Tap #" .. instances .. ": " .. os.date() .. ")"
        --"Subnets Statistics (Tap #" .. instances .. ": Filter: " .. get_filter() .. ")"
    )
    tapwin:set("")

    --[ Text Builders ]vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
    local function build_ip_text()
        taptext.ip = ""

        -- Sort
        local a = {}
        for n in pairs(tapdata.ip) do
            table.insert(a, n)
        end
        table.sort(a)
    --[[
        -- Verify we're working with sorted, positive values
        for i, v in ipairs(a) do
            print(i, v)
        end
    --]]

        -- Build the text one line at a time
        for i, n in ipairs(a) do
            local line = string.format("%-20s\t%d\t%d\t%d\t%d\t%d\t%d\n",
                tapdata.ip[n].subnet,
                tapdata.ip[n].packets, tapdata.ip[n].bytes,
                tapdata.ip[n].tx_packets, tapdata.ip[n].tx_bytes,
                tapdata.ip[n].rx_packets, tapdata.ip[n].rx_bytes)
            taptext.ip = taptext.ip .. line
        end

    --[[
        -- Print the subnets (unsorted)
        for i, td in pairs(tapdata.ip) do
            local line = string.format("%-20s\t%d\t%d\t%d\t%d\t%d\t%d\n",
                td.subnet,
                td.packets, td.bytes,
                td.tx_packets, td.tx_bytes,
                td.rx_packets, td.rx_bytes)
            taptext.ip = taptext.ip .. line
        end
    --]]

        if string.len(taptext.ip) > 0 then
            taptext.ip = string.format(
                --"Filter: " .. get_filter() .. "\n\n" ..
                "%-20s\tPackets\tBytes\tTx Packets\tTx Bytes\tRx Packets\tRx Bytes\n" ..
                "-----------------\t-------\t-----\t----------\t--------\t----------\t--------\n",
                "Subnet (" .. ((settings.subnet_bits < 1 or settings.subnet_bits > 32) and "Classful" or
                 settings.subnet_bits) ..")") .. taptext.ip .. "\n"
        end
        return taptext.ip
    end -- build_ip_text()

    local function build_all_text()
        taptext.all = build_ip_text() .. "\n"
        return taptext.all
    end -- build_all_text()
    --[ Text Builders ]^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    --[ BUTTONS ]vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
     --[ Subnet Bits ] Set the number of subnet bits
    tapwin:add_button("Subnet Bits", function()

        local function set_subnet_bits(inputstr)
            if inputstr == nil then
                -- Nothing entered
                return
            end
            settings.subnet_bits = tonumber(inputstr)
        end -- set_subnet_bits()

        new_dialog("Subnet bits", set_subnet_bits, "Enter subnet bits 1-32 (0 for Classful Subnets)")
    end)

     --[ Copy ] Copy the current window text to the clipboard
    tapwin:add_button("Copy", function()
        copy_to_clipboard(tapwin:get_text())
    end)
    --[ BUTTONS ]^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    -- Our taps (only 1 so far)
    local taps = {
        -- TODO: Too bad get_filter() doesn't seem to work.  Bug?  IDK.
        ip = Listener.new("frame", "ip.addr")
        --ip = Listener.new("frame", get_filter())
    }

    -- Callback to remove the taps when the window closes
    local function remove_taps()
        taps.ip:remove()
    end -- remove_taps()

    -- Make sure the taps don't hang around after the window was closed
    tapwin:set_atclose(remove_taps)

    --[[
        The taps.foo.packet() function will be called for every packet that
        matches the respective filter.
    --]]
    function taps.ip.packet(pinfo, tvb)

        if ip_src() == nil or ip_dst() == nil then
            return
        end

        local subnet_str
        local first_octet

        -----------------
        -- Source Address
        -----------------
        local src_range = ip_src().range
        local src_val = src_range:uint()
        local src_subnet_val

        -- https://osqa-ask.wireshark.org/questions/30478/bit-operation-returns-negative-number-that-doesnt-make-sense
        local function unsign(n)
            if n < 0 then
                n = 4294967296 + n
            end
            return n
        end -- unsign()

        if settings.subnet_bits < 1 or settings.subnet_bits > 32 then
            -- Classful subnets
            first_octet = src_range(0, 1):uint()
            if first_octet >= 224 then
                --[[
                    Source Address is Class D or E.
                    This should never happen, but OK.  Use a /32?
                --]]
                src_subnet_val = src_val
            elseif first_octet >= 192 then
                -- Class C (/24)
                src_subnet_val = bit.band(src_val, 0xffffff00)
            elseif first_octet >= 128 then
                -- Class B (/16)
                src_subnet_val = bit.band(src_val, 0xffff0000)
            else
                -- Class A (/8)
                src_subnet_val = bit.band(src_val, 0xff000000)
            end
        else
            -- The settings.subnet_bits specifies the subnet_mask
            src_subnet_val = bit.band(src_val, subnet_mask[settings.subnet_bits])
        end

        src_subnet_val = unsign(src_subnet_val)
        subnet_str =
                bit.band(bit.rshift(src_subnet_val, 24), 0xff) .. "." ..
                bit.band(bit.rshift(src_subnet_val, 16), 0xff) .. "." ..
                bit.band(bit.rshift(src_subnet_val, 8), 0xff) .. "." ..
                bit.band(src_subnet_val, 0xff)

        if tapdata.ip[src_subnet_val] == nil then
            tapdata.ip[src_subnet_val] = {
                subnet = subnet_str,
                packets = 1,
                bytes = frame_len().value,
                tx_packets = 1,
                tx_bytes = frame_len().value,
                rx_packets = 0,
                rx_bytes = 0
            }
        else
            tapdata.ip[src_subnet_val].packets = tapdata.ip[src_subnet_val].packets + 1
            tapdata.ip[src_subnet_val].bytes = tapdata.ip[src_subnet_val].bytes + frame_len().value
            tapdata.ip[src_subnet_val].tx_packets = tapdata.ip[src_subnet_val].tx_packets + 1
            tapdata.ip[src_subnet_val].tx_bytes = tapdata.ip[src_subnet_val].tx_bytes + frame_len().value
        end

        ----------------------
        -- Destination Address
        ----------------------
        local dst_range = ip_dst().range
        local dst_val = dst_range:uint()
        local dst_subnet_val

        if settings.subnet_bits < 1 or settings.subnet_bits > 32 then
            -- Classful subnets
            first_octet = dst_range(0, 1):uint()
            if first_octet >= 224 then
                -- Destination Address is Class D or E.  Use a /32?
                dst_subnet_val = dst_val
            elseif first_octet >= 192 then
                -- Class C (/24)
                dst_subnet_val = bit.band(dst_val, 0xffffff00)
            elseif first_octet >= 128 then
                -- Class B (/16)
                dst_subnet_val = bit.band(dst_val, 0xffff0000)
            else
                -- Class A (/8)
                dst_subnet_val = bit.band(dst_val, 0xff000000)
            end
        else
            -- The settings.subnet_bits specifies the subnet_mask
            dst_subnet_val = bit.band(dst_val, subnet_mask[settings.subnet_bits])
        end

        dst_subnet_val = unsign(dst_subnet_val)
        subnet_str =
                bit.band(bit.rshift(dst_subnet_val, 24), 0xff) .. "." ..
                bit.band(bit.rshift(dst_subnet_val, 16), 0xff) .. "." ..
                bit.band(bit.rshift(dst_subnet_val, 8), 0xff) .. "." ..
                bit.band(dst_subnet_val, 0xff)

        if tapdata.ip[dst_subnet_val] == nil then
            tapdata.ip[dst_subnet_val] = {
                subnet = subnet_str,
                packets = 1,
                bytes = frame_len().value,
                tx_packets = 0,
                tx_bytes = 0,
                rx_packets = 1,
                rx_bytes = frame_len().value
            }
        else
            tapdata.ip[dst_subnet_val].rx_packets = tapdata.ip[dst_subnet_val].rx_packets + 1
            tapdata.ip[dst_subnet_val].rx_bytes = tapdata.ip[dst_subnet_val].rx_bytes + frame_len().value

            if dst_subnet_val ~= src_subnet_val then
                tapdata.ip[dst_subnet_val].packets = tapdata.ip[dst_subnet_val].packets + 1
                tapdata.ip[dst_subnet_val].bytes = tapdata.ip[dst_subnet_val].bytes + frame_len().value
            end
        end

    end -- taps.ip.packet()

    --[[
        The taps.foo.draw() function will be called once every few seconds to
        redraw the window, but since we're only building a static snapshot
        of subnet statistics once the window is first created, this function
        does nothing.  If you want updated information, for example, during
        a live capture, then you'll need to open a new window for the
        information to be updated.
    --]]
    function taps.ip.draw()
    end -- taps.ip.draw()

    --[[
        The taps.foo.reset() function will be called whenever a reset is needed
        e.g. when reloading the capture file.  Except in this case, reloading
        the capture file is just going to cause the same data to be populated,
        and clearing the window also means we wouldn't be able to keep the
        old window data around when a new capture file is loaded, which could
        come in handy if we wanted to compare a set of resolved data from one
        capture file to the next.  Therefore, don't actually reset anything.
    --]]
    function taps.ip.reset()
        --[[
            tapwin:clear()
            tapdata.ip = {}
            taptext.ip = {}
        --]]
    end -- taps.ip.reset()

    -- Ensure that all existing packets are processed.
    retap_packets()

    -- Build all the text strings, then display everything
    tapwin:set(build_all_text())

    --[[
    -- Print a list of tap listeners to stdout.
    for _,tap_name in pairs(Listener.list()) do
            print(tap_name)
    end
    --]]

end -- subnets_statistics_window()

--[[
    Optional 3rd parameter to register_menu.
    See https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Gui.html#global_functions_Gui
    If omitted, defaults to MENU_STAT_GENERIC. Other options include:

    MENU_STAT_UNSORTED (Statistics),
    MENU_STAT_GENERIC (Statistics, first section),
    MENU_STAT_CONVERSATION (Statistics/Conversation List),
    MENU_STAT_ENDPOINT (Statistics/Endpoint List),
    MENU_STAT_RESPONSE (Statistics/Service Response Time),
    MENU_STAT_TELEPHONY (Telephony),
    MENU_STAT_TELEPHONY_ANSI (Telephony/ANSI),
    MENU_STAT_TELEPHONY_GSM (Telephony/GSM),
    MENU_STAT_TELEPHONY_LTE (Telephony/LTE),
    MENU_STAT_TELEPHONY_MTP3 (Telephony/MTP3),
    MENU_STAT_TELEPHONY_SCTP (Telephony/SCTP),
    MENU_ANALYZE (Analyze),
    MENU_ANALYZE_CONVERSATION (Analyze/Conversation Filter),
    MENU_TOOLS_UNSORTED (Tools). (number)

    The only one that seems to work is MENU_TOOLS_UNSORTED, so use that one.
--]]
register_menu("Subnets Statistics", subnets_statistics_window, MENU_TOOLS_UNSORTED)

--print("tap-subnets registered")
