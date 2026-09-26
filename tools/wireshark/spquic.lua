-- Smithproxy Decrypted QUIC (SPQ1) Wireshark dissector.
--
-- SPQ1 keeps a QUIC-shaped long header and carries ordinary, unencrypted QUIC
-- frames. The private version marker makes exported traffic self-identifying
-- without pretending that it is decryptable QUIC v1 wire traffic.

local spquic = Proto("spquic", "Smithproxy Decrypted QUIC")
local sphttp3 = Proto("sphttp3", "HTTP/3 (Smithproxy decrypted)")

local f_version = ProtoField.string("spquic.version", "Export Version")
local f_first = ProtoField.uint8("spquic.first_byte", "First Byte", base.HEX)
local f_session = ProtoField.uint64("spquic.session_id", "Session ID", base.DEC)
local f_packet = ProtoField.uint32("spquic.packet_number", "Packet Number", base.DEC)
local f_alpn = ProtoField.string("spquic.alpn", "Application Protocol (ALPN)")
local f_frame_type = ProtoField.uint8("spquic.frame_type", "Frame Type", base.HEX)
local f_stream = ProtoField.uint64("spquic.stream_id", "Stream ID", base.DEC)
local f_offset = ProtoField.uint64("spquic.offset", "Stream Offset", base.DEC)
local f_length = ProtoField.uint64("spquic.length", "Data Length", base.DEC)
local f_fin = ProtoField.bool("spquic.fin", "FIN")
local f_header_end = ProtoField.string("spquic.header_end", "Header End")
local f_data = ProtoField.bytes("spquic.data", "Decrypted Stream Data")
local f_h3_stream = ProtoField.uint64("sphttp3.stream_id", "Stream ID", base.DEC)
local f_h3_header = ProtoField.string("sphttp3.header", "Header")
local f_h3_method = ProtoField.string("sphttp3.method", "Method")
local f_h3_scheme = ProtoField.string("sphttp3.scheme", "Scheme")
local f_h3_authority = ProtoField.string("sphttp3.authority", "Authority")
local f_h3_path = ProtoField.string("sphttp3.path", "Path")
local f_h3_status = ProtoField.string("sphttp3.status", "Status")

spquic.fields = {
    f_version,
    f_first,
    f_session,
    f_packet,
    f_alpn,
    f_frame_type,
    f_stream,
    f_offset,
    f_length,
    f_fin,
    f_header_end,
    f_data,
}

sphttp3.fields = {
    f_h3_stream,
    f_h3_header,
    f_h3_method,
    f_h3_scheme,
    f_h3_authority,
    f_h3_path,
    f_h3_status,
}

local function read_varint(buffer, offset)
    if offset >= buffer:len() then return nil end
    local first = buffer(offset, 1):uint()
    local size = 2 ^ bit.rshift(first, 6)
    if offset + size > buffer:len() then return nil end

    -- Lua numbers exactly represent all values used by the test fixture. The
    -- original encoded bytes are also attached to each uint64 field below.
    local value = bit.band(first, 0x3f)
    for index = 1, size - 1 do
        value = value * 256 + buffer(offset + index, 1):uint()
    end
    return value, size
end

local function add_varint(tree, field, buffer, offset, value, size)
    local item = tree:add(field, buffer(offset, size))
    item:set_text(field.name .. ": " .. tostring(value))
end

local function dissect_stream_frame(buffer, offset, root)
    local frame_type = buffer(offset, 1):uint()
    local frame = root:add(spquic, buffer(offset), "QUIC STREAM Frame")
    frame:add(f_frame_type, buffer(offset, 1))
    frame:add(f_fin, bit.band(frame_type, 0x01) ~= 0)
    offset = offset + 1

    local stream_id, stream_size = read_varint(buffer, offset)
    if not stream_id then return buffer:len() end
    add_varint(frame, f_stream, buffer, offset, stream_id, stream_size)
    offset = offset + stream_size

    local stream_offset = 0
    if bit.band(frame_type, 0x04) ~= 0 then
        local offset_size
        stream_offset, offset_size = read_varint(buffer, offset)
        if not stream_offset then return buffer:len() end
        add_varint(frame, f_offset, buffer, offset, stream_offset, offset_size)
        offset = offset + offset_size
    end

    local data_length = buffer:len() - offset
    if bit.band(frame_type, 0x02) ~= 0 then
        local length_size
        data_length, length_size = read_varint(buffer, offset)
        if not data_length then return buffer:len() end
        add_varint(frame, f_length, buffer, offset, data_length, length_size)
        offset = offset + length_size
    end

    -- SPQ1 adds a human-visible delimiter after the ordinary STREAM metadata.
    -- It is not included in Data Length and never reaches the displayed data.
    if offset + 3 > buffer:len() or buffer(offset, 3):string() ~= ">>>" then
        frame:add_expert_info(PI_MALFORMED, PI_ERROR, "Missing SPQ1 header delimiter")
        return buffer:len()
    end
    frame:add(f_header_end, buffer(offset, 3), ">>>")
    offset = offset + 3

    if data_length > buffer:len() - offset then data_length = buffer:len() - offset end
    if data_length > 0 then frame:add(f_data, buffer(offset, data_length)) end
    return offset + data_length
end

local function dissect_h3_headers(buffer, offset, root, pinfo)
    local extension_type, type_size = read_varint(buffer, offset)
    if extension_type ~= 0xface then return buffer:len() end
    offset = offset + type_size

    local extension_length, length_size = read_varint(buffer, offset)
    if not extension_length then return buffer:len() end
    offset = offset + length_size
    local extension_end = offset + extension_length
    if extension_end > buffer:len() then
        root:add_expert_info(PI_MALFORMED, PI_ERROR, "Truncated SPQ1 H3 record")
        return buffer:len()
    end

    local h3 = root:add(sphttp3, buffer(offset, extension_length),
                        "HTTP/3 decoded HEADERS")
    local record_type = buffer(offset, 1):uint()
    offset = offset + 1
    if record_type ~= 1 then
        h3:add_expert_info(PI_PROTOCOL, PI_WARN, "Unknown SPQ1 H3 record type")
        return extension_end
    end

    local stream_id, stream_size = read_varint(buffer, offset)
    if not stream_id then return extension_end end
    add_varint(h3, f_h3_stream, buffer, offset, stream_id, stream_size)
    offset = offset + stream_size

    local field_count, count_size = read_varint(buffer, offset)
    if not field_count then return extension_end end
    offset = offset + count_size
    local summary_method, summary_path, summary_status

    for _ = 1, field_count do
        local name_length, name_size = read_varint(buffer, offset)
        if not name_length then return extension_end end
        offset = offset + name_size
        if offset + name_length > extension_end then return extension_end end
        local name = buffer(offset, name_length):string()
        offset = offset + name_length

        local value_length, value_size = read_varint(buffer, offset)
        if not value_length then return extension_end end
        offset = offset + value_size
        if offset + value_length > extension_end then return extension_end end
        local value = buffer(offset, value_length):string()
        offset = offset + value_length

        h3:add(f_h3_header, name .. ": " .. value)
        if name == ":method" then
            h3:add(f_h3_method, value); summary_method = value
        elseif name == ":scheme" then h3:add(f_h3_scheme, value)
        elseif name == ":authority" then h3:add(f_h3_authority, value)
        elseif name == ":path" then
            h3:add(f_h3_path, value); summary_path = value
        elseif name == ":status" then
            h3:add(f_h3_status, value); summary_status = value
        end
    end

    if offset + 3 <= extension_end and buffer(offset, 3):string() == ">>>" then
        h3:add(f_header_end, buffer(offset, 3), ">>>")
    end
    pinfo.cols.protocol:set("HTTP3/SPQ1")
    if summary_method then
        pinfo.cols.info:set(summary_method .. " " .. (summary_path or ""))
    elseif summary_status then
        pinfo.cols.info:set("HTTP/3 " .. summary_status)
    end
    return extension_end
end

function spquic.dissector(buffer, pinfo, tree)
    if buffer:len() < 16 or buffer(1, 4):string() ~= "SPQ1" then return 0 end

    pinfo.cols.protocol:set("SPQUIC")
    local root = tree:add(spquic, buffer(), "Smithproxy Decrypted QUIC")
    local first = buffer(0, 1):uint()
    root:add(f_first, buffer(0, 1))
    root:add(f_version, "SPQ1")

    local offset = 5
    local destination_length = buffer(offset, 1):uint()
    offset = offset + 1
    if offset + destination_length > buffer:len() then return buffer:len() end
    if destination_length == 8 then root:add(f_session, buffer(offset, 8)) end
    offset = offset + destination_length

    if offset >= buffer:len() then return buffer:len() end
    local source_length = buffer(offset, 1):uint()
    offset = offset + 1 + source_length

    local packet_length, length_size = read_varint(buffer, offset)
    if not packet_length then return buffer:len() end
    offset = offset + length_size

    local packet_number_size = bit.band(first, 0x03) + 1
    if offset + packet_number_size > buffer:len() then return buffer:len() end
    root:add(f_packet, buffer(offset, packet_number_size))
    offset = offset + packet_number_size

    -- ALPN is explicit in SPQ1 because the TLS handshake is intentionally not
    -- exported. Keeping it in every packet also makes sampled captures useful.
    if offset >= buffer:len() then return buffer:len() end
    local alpn_length = buffer(offset, 1):uint()
    offset = offset + 1
    if offset + alpn_length > buffer:len() then
        root:add_expert_info(PI_MALFORMED, PI_ERROR, "Truncated SPQ1 ALPN")
        return buffer:len()
    end
    root:add(f_alpn, buffer(offset, alpn_length))
    offset = offset + alpn_length

    -- Do not blindly forward the following bytes through Wireshark's
    -- quic.proto table. Native HTTP/3 expects conversation-owned QUIC stream
    -- and reassembly context in addition to the ALPN string. SPQ1 exposes ALPN
    -- for filtering and for a future context-aware application dispatcher.

    while offset < buffer:len() do
        local frame_type = read_varint(buffer, offset)
        if not frame_type then break end
        if frame_type >= 0x08 and frame_type <= 0x0f then
            offset = dissect_stream_frame(buffer, offset, root)
        elseif frame_type == 0xface then
            offset = dissect_h3_headers(buffer, offset, root, pinfo)
        else
            root:add(f_frame_type, buffer(offset, 1)):append_text(" (unsupported)")
            break
        end
    end
    return buffer:len()
end

spquic:register_heuristic("udp", function(buffer, pinfo, tree)
    if buffer:len() < 5 or buffer(1, 4):string() ~= "SPQ1" then return false end
    spquic.dissector(buffer, pinfo, tree)
    return true
end)
