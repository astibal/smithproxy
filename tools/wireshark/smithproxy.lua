-- Smithproxy PCAPNG Custom Block dissector
-- PEN 67005; namespaces SXME, SXST, SXTL and SXPP.

local sx = Proto("smithproxy", "Smithproxy Capture Metadata")

local namespaces = {
    SXME = "Connection Metadata",
    SXST = "Connection Statistics",
    SXTL = "TLS Profile",
    SXPP = "Protocol Profile",
}

local f_namespace = ProtoField.string("smithproxy.namespace", "Namespace")
local f_entry_type = ProtoField.uint16("smithproxy.entry_type", "Entry type", base.DEC)
local f_version = ProtoField.uint16("smithproxy.version", "Version", base.DEC)
local f_payload_length = ProtoField.uint32("smithproxy.payload_length", "Payload length", base.DEC)
local f_payload = ProtoField.bytes("smithproxy.payload", "Payload")
local f_json = ProtoField.string("smithproxy.json", "JSON payload")
local f_schema = ProtoField.string("smithproxy.schema", "Schema")
local f_session_id = ProtoField.string("smithproxy.session_id", "Session ID")
local f_session_key = ProtoField.string("smithproxy.proxy_session_key", "Proxy session key")
local f_flow_protocol = ProtoField.string("smithproxy.flow.protocol", "Flow protocol")
local f_flow_src = ProtoField.string("smithproxy.flow.src", "Flow source")
local f_flow_dst = ProtoField.string("smithproxy.flow.dst", "Flow destination")
local f_flow_src_port = ProtoField.uint16("smithproxy.flow.src_port", "Flow source port", base.DEC)
local f_flow_dst_port = ProtoField.uint16("smithproxy.flow.dst_port", "Flow destination port", base.DEC)

local f_pp_seq = ProtoField.uint64("smithproxy.pp.seq", "Sequence", base.DEC)
local f_pp_timestamp = ProtoField.string("smithproxy.pp.timestamp", "Timestamp")
local f_pp_unix_us = ProtoField.uint64("smithproxy.pp.timestamp_unix_us", "Unix timestamp (us)", base.DEC)
local f_pp_delta_us = ProtoField.uint64("smithproxy.pp.delta_us", "Delta (us)", base.DEC)
local f_pp_side = ProtoField.string("smithproxy.pp.side", "Side")
local f_pp_component = ProtoField.string("smithproxy.pp.component", "Component")
local f_pp_scope = ProtoField.string("smithproxy.pp.scope", "Scope")
local f_pp_stream_id = ProtoField.uint64("smithproxy.pp.stream_id", "Stream ID", base.DEC)
local f_pp_event = ProtoField.string("smithproxy.pp.event", "Event")
local f_pp_status = ProtoField.string("smithproxy.pp.status", "Status")
local f_pp_detail = ProtoField.string("smithproxy.pp.detail", "Detail")

local malformed = ProtoExpert.new(
    "smithproxy.malformed", "Malformed Smithproxy custom block",
    expert.group.MALFORMED, expert.severity.ERROR)
local unsupported = ProtoExpert.new(
    "smithproxy.unsupported", "Unsupported Smithproxy entry type or version",
    expert.group.PROTOCOL, expert.severity.WARN)

sx.fields = {
    f_namespace, f_entry_type, f_version, f_payload_length, f_payload,
    f_json, f_schema, f_session_id, f_session_key, f_flow_protocol,
    f_flow_src, f_flow_dst, f_flow_src_port, f_flow_dst_port,
    f_pp_seq, f_pp_timestamp, f_pp_unix_us, f_pp_delta_us, f_pp_side,
    f_pp_component, f_pp_scope, f_pp_stream_id, f_pp_event, f_pp_status,
    f_pp_detail,
}
sx.experts = {malformed, unsupported}

local json_dissector = Dissector.get("json")

local function csv_fields(line)
    local result, field, quoted, i = {}, {}, false, 1
    while i <= #line do
        local c = line:sub(i, i)
        if quoted then
            if c == '"' and line:sub(i + 1, i + 1) == '"' then
                field[#field + 1] = '"'
                i = i + 1
            elseif c == '"' then
                quoted = false
            else
                field[#field + 1] = c
            end
        elseif c == '"' and #field == 0 then
            quoted = true
        elseif c == ',' then
            result[#result + 1] = table.concat(field)
            field = {}
        else
            field[#field + 1] = c
        end
        i = i + 1
    end
    result[#result + 1] = table.concat(field)
    return result, not quoted
end

local function json_string(payload, key)
    -- Smithproxy emits compact JSON. This indexes common correlation fields;
    -- the built-in JSON dissector below remains authoritative for full parsing.
    local escaped = key:gsub("([^%w])", "%%%1")
    return payload:match('"' .. escaped .. '"%s*:%s*"([^"\\]*)"')
end

local function add_json(payload_tvb, payload, pinfo, tree)
    tree:add(f_json, payload_tvb, payload)
    local schema = json_string(payload, "schema")
    local session_id = json_string(payload, "session_id")
    local session_key = json_string(payload, "proxy_session_key")
    if schema then tree:add(f_schema, schema) end
    if session_id then tree:add(f_session_id, session_id) end
    if session_key then tree:add(f_session_key, session_key) end
    if json_dissector then json_dissector:call(payload_tvb:tvb(), pinfo, tree) end
    return schema or "JSON", session_key
end

local function add_uint64(tree, field, value)
    if value and value ~= "" then tree:add(field, UInt64(value)) end
end

local function add_protocol_profile(payload_tvb, payload, version, tree)
    local values, complete = csv_fields(payload)
    local expected = version == 2 and 13 or 11
    if not complete or #values ~= expected then
        tree:add_proto_expert_info(malformed,
            string.format("SXPP v%d requires exactly %d RFC 4180 CSV fields", version, expected))
        tree:add(f_payload, payload_tvb)
        return "malformed SXPP", nil
    end
    local sequence, timestamp, unix_us, delta_us, side, component, scope
    local stream_id, event, status, detail, session_key
    if version == 2 then
        timestamp, unix_us, delta_us = values[1], values[2], values[3]
        tree:add(f_session_id, values[4])
        tree:add(f_session_key, values[5])
        session_key = values[5]
        sequence, side, component, scope = values[6], values[7], values[8], values[9]
        stream_id, event, status, detail = values[10], values[11], values[12], values[13]
    else
        sequence, timestamp, unix_us, delta_us = values[1], values[2], values[3], values[4]
        side, component, scope = values[5], values[6], values[7]
        stream_id, event, status, detail = values[8], values[9], values[10], values[11]
    end
    add_uint64(tree, f_pp_seq, sequence)
    tree:add(f_pp_timestamp, timestamp)
    add_uint64(tree, f_pp_unix_us, unix_us)
    add_uint64(tree, f_pp_delta_us, delta_us)
    tree:add(f_pp_side, side)
    tree:add(f_pp_component, component)
    tree:add(f_pp_scope, scope)
    add_uint64(tree, f_pp_stream_id, stream_id)
    tree:add(f_pp_event, event)
    tree:add(f_pp_status, status)
    tree:add(f_pp_detail, detail)
    return string.format("#%s %s %s/%s %s",
        sequence, side, component, scope, event), session_key
end

local function attach_flow(session_key, pinfo, tree)
    if not session_key then return end
    local protocol, src, src_port, dst, dst_port =
        session_key:match("^([^_]+)_(.-):(%d+)%-(.-):(%d+)$")
    if not protocol then return end
    local function address(value)
        if value:find(":", 1, true) then return Address.ipv6(value) end
        return Address.ip(value)
    end
    local ok_src, src_address = pcall(address, src)
    local ok_dst, dst_address = pcall(address, dst)
    if not ok_src or not ok_dst then return end
    src_port, dst_port = tonumber(src_port), tonumber(dst_port)
    if not src_port or not dst_port or src_port > 65535 or dst_port > 65535 then return end
    if protocol ~= "tcp" and protocol ~= "udp" and protocol ~= "quic" then return end
    tree:add(f_flow_protocol, protocol)
    tree:add(f_flow_src, src)
    tree:add(f_flow_dst, dst)
    tree:add(f_flow_src_port, src_port)
    tree:add(f_flow_dst_port, dst_port)
    pinfo.src, pinfo.net_src, pinfo.src_port = src_address, src_address, src_port
    pinfo.dst, pinfo.net_dst, pinfo.dst_port = dst_address, dst_address, dst_port
    -- Wireshark's port_type enum is PT_NONE=0, PT_SCTP=1, PT_TCP=2,
    -- PT_UDP=3. WSLua exposes pinfo.port_type but not symbolic constants.
    pinfo.port_type = (protocol == "udp" or protocol == "quic") and 3 or 2
    local ctype = (protocol == "udp" or protocol == "quic") and convtypes.UDP or convtypes.TCP
    Conversation.find(pinfo.number, ctype, src_address, dst_address,
                      src_port, dst_port, true)
end

function sx.dissector(tvb, pinfo, tree)
    if tvb:len() < 12 then
        tree:add_proto_expert_info(malformed, "Envelope is shorter than 12 bytes")
        return tvb:len()
    end

    local namespace = tvb(0, 4):string()
    local entry_type = tvb(4, 2):le_uint()
    local version = tvb(6, 2):le_uint()
    local payload_length = tvb(8, 4):le_uint()
    local little_endian = true
    if payload_length > tvb:len() - 12 then
        entry_type = tvb(4, 2):uint()
        version = tvb(6, 2):uint()
        payload_length = tvb(8, 4):uint()
        little_endian = false
    end

    local root = tree:add(sx, tvb(), namespaces[namespace] or "Unknown namespace")
    root:add(f_namespace, tvb(0, 4), namespace)
    if little_endian then
        root:add_le(f_entry_type, tvb(4, 2))
        root:add_le(f_version, tvb(6, 2))
        root:add_le(f_payload_length, tvb(8, 4))
    else
        root:add(f_entry_type, tvb(4, 2))
        root:add(f_version, tvb(6, 2))
        root:add(f_payload_length, tvb(8, 4))
    end

    if payload_length > tvb:len() - 12 then
        root:add_proto_expert_info(malformed, "Payload length exceeds custom block data")
        return tvb:len()
    end
    local supported_version = version == 1 or (namespace == "SXPP" and version == 2)
    if entry_type ~= 1 or not supported_version then
        root:add_proto_expert_info(unsupported,
            string.format("entry_type=%d version=%d", entry_type, version))
        root:add(f_payload, tvb(12, payload_length))
        pinfo.cols.protocol = "Smithproxy"
        pinfo.cols.info = string.format("Smithproxy %s: unsupported type=%d version=%d",
                                       namespace, entry_type, version)
        return tvb:len()
    end

    local payload_tvb = tvb(12, payload_length)
    local payload = payload_tvb:string()
    local summary, session_key
    if namespace == "SXPP" then
        summary, session_key = add_protocol_profile(payload_tvb, payload, version, root)
    elseif namespace == "SXME" or namespace == "SXST" or namespace == "SXTL" then
        summary, session_key = add_json(payload_tvb, payload, pinfo, root)
    else
        root:add(f_payload, payload_tvb)
        summary = "unknown namespace"
    end
    attach_flow(session_key, pinfo, root)

    pinfo.cols.protocol = namespace
    pinfo.cols.info = string.format("Smithproxy %s v%d: %s", namespace, version, summary)
    return tvb:len()
end

local custom_blocks = DissectorTable.get("pcapng_custom_block")
custom_blocks:add(67005, sx)
