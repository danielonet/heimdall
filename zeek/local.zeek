# Heimdall site policy for Zeek.
#
# Verified against a live zeek/zeek:latest container (Zeek 8.2.1,
# 2026-07-24): dns.log/conn.log land in /var/log/zeek as JSON lines exactly
# as sentinel/security/zeek_parser.py expects (id.orig_h/id.resp_h/ts/query
# field names confirmed against real output). files.log did not match: it
# was originally read via tx_hosts/rx_hosts, a schema Zeek replaced in v5.1
# with one files.log entry per connection (sharing a fuid) using
# id.orig_h/id.resp_h/is_orig instead — see
# ZeekFileExtractionWatcher._load_fuid_to_source_ip for the fix.

# JSON logs, not the default TSV — sentinel/security/zeek_parser.py parses
# dns.log/conn.log/files.log as JSON Lines.
redef LogAscii::use_json = T;

# Site::local_nets isn't needed for the files.log attribution above (that
# comes from the connection's own id.orig_h/id.resp_h, regardless of
# local_nets) — it's what drives conn.log's local_orig/local_resp fields
# and Zeek's notice/weird framework instead, both worth having correct.
# Read from LAN_SUBNET so it's configured the same way SNIFF_IFACE is (see
# docker-compose.yml's zeek service), rather than hardcoding one
# household's subnet into the image.
#
# Site::local_nets is a &redef'able option, so it must be extended with a
# plain top-level `redef`, not an assignment inside an event handler — but
# a top-level redef is evaluated unconditionally at load time, and
# to_subnet("") on an unset LAN_SUBNET is a fatal error that would crash
# Zeek before it ever starts sniffing. safe_lan_subnet() below falls back to
# a harmless no-op subnet instead; the zeek_init() handler separately warns
# (rather than crashing) so a missing LAN_SUBNET is visible in the logs.
function safe_lan_subnet(): subnet
    {
    local raw = getenv("LAN_SUBNET");
    if ( raw == "" )
        return 0.0.0.0/32;
    return to_subnet(raw);
    }

redef Site::local_nets += { safe_lan_subnet() };

event zeek_init()
    {
    if ( getenv("LAN_SUBNET") == "" )
        Reporter::warning("LAN_SUBNET is not set — conn.log's local_orig/local_resp " +
            "and Zeek's notice/weird framework will misclassify every host as remote");
    }

# Curated file extraction — sentinel/security/zeek_parser.py's
# ZeekFileExtractionWatcher feeds every extracted file to ClamAV. Only pull
# bytes to disk for MIME types that are realistic malware-delivery vectors
# (executables, archives, opaque binary blobs); extracting every image/
# video/web asset a home network sees would be far heavier on disk and CPU
# than this box needs — see docs/architecture/06-security-services.md's
# ClamAV section for the reasoning.
@load base/files/extract

redef FileExtract::prefix = "/var/zeek/extracted/";

const extract_mime_types: set[string] = {
    "application/x-dosexec",
    "application/x-executable",
    "application/x-sharedlib",
    "application/zip",
    "application/x-rar-compressed",
    "application/x-7z-compressed",
    "application/octet-stream",
} &redef;

event file_sniff(f: fa_file, meta: fa_metadata)
    {
    if ( ! meta?$mime_type )
        return;

    if ( meta$mime_type in extract_mime_types )
        Files::add_analyzer(f, Files::ANALYZER_EXTRACT);
    }
