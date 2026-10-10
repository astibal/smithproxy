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
    f_json, f_schema, f_session_id, f_session_key,
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
    return schema or "JSON"
end

local function add_uint64(tree, field, value)
    if value and value ~= "" then tree:add(field, UInt64(value)) end
end

local function add_protocol_profile(payload_tvb, payload, tree)
    local values, complete = csv_fields(payload)
    if not complete or #values ~= 11 then
        tree:add_proto_expert_info(malformed, "SXPP requires exactly 11 RFC 4180 CSV fields")
        tree:add(f_payload, payload_tvb)
        return "malformed SXPP"
    end
    add_uint64(tree, f_pp_seq, values[1])
    tree:add(f_pp_timestamp, values[2])
    add_uint64(tree, f_pp_unix_us, values[3])
    add_uint64(tree, f_pp_delta_us, values[4])
    tree:add(f_pp_side, values[5])
    tree:add(f_pp_component, values[6])
    tree:add(f_pp_scope, values[7])
    add_uint64(tree, f_pp_stream_id, values[8])
    tree:add(f_pp_event, values[9])
    tree:add(f_pp_status, values[10])
    tree:add(f_pp_detail, values[11])
    return string.format("#%s %s %s/%s %s",
        values[1], values[5], values[6], values[7], values[9])
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
    if entry_type ~= 1 or version ~= 1 then
        root:add_proto_expert_info(unsupported,
            string.format("entry_type=%d version=%d", entry_type, version))
    end

    local payload_tvb = tvb(12, payload_length)
    local payload = payload_tvb:string()
    local summary
    if namespace == "SXPP" then
        summary = add_protocol_profile(payload_tvb, payload, root)
    elseif namespace == "SXME" or namespace == "SXST" or namespace == "SXTL" then
        summary = add_json(payload_tvb, payload, pinfo, root)
    else
        root:add(f_payload, payload_tvb)
        summary = "unknown namespace"
    end

    pinfo.cols.protocol = namespace
    pinfo.cols.info = string.format("Smithproxy %s v%d: %s", namespace, version, summary)
    return tvb:len()
end

local custom_blocks = DissectorTable.get("pcapng_custom_block")
custom_blocks:add(67005, sx)
