<?php

require_once __DIR__ . "/../vendor/autoload.php";

function _ip(array $array)
{
    return $array["ip"];
}

function _target(array $array)
{
    return $array["target"];
}

// Basic functionality checks. There is a chance this might fail due to using
// different nameservers as dns_get_record() will use system defaults.

$native = array_map("_ip", dns_get_record("bbc.com", DNS_A));
$resolv = array_map("_ip", resolv_get_records("bbc.com", DNS_A, 5, "8.8.8.8"));

if (sizeof(array_diff($native, $resolv)) || sizeof(array_diff($resolv, $native))) {
    echo "Failed check for bcc.com A records\n";
    var_dump($native);
    var_dump($resolv);
    exit(1);
}

$native = array_map("_target", dns_get_record("bbc.com", DNS_MX));
$resolv = array_map("_target", resolv_get_records("bbc.com", DNS_MX, 5, "8.8.8.8"));

if (sizeof(array_diff($native, $resolv)) || sizeof(array_diff($resolv, $native))) {
    echo "Failed check for bcc.com MX records\n";
    var_dump($native);
    var_dump($resolv);
    exit(1);
}

// test tcp mode
$native = array_map("_ip", dns_get_record("bbc.com", DNS_A));
$resolv = array_map(
    "_ip",
    _resolv_convert_results(
        _resolv_query_tcp("bbc.com", 5, "8.8.8.8", _resolv_convert_query(DNS_A))[1],
        "bbc.com"
    )
);

if (sizeof(array_diff($native, $resolv)) || sizeof(array_diff($resolv, $native))) {
    echo "Failed TCP check for bcc.com A records\n";
    var_dump($native);
    var_dump($resolv);
    exit(1);
}

$native = array_map("_target", dns_get_record("bbc.com", DNS_MX));
$resolv = array_map(
    "_target",
    _resolv_convert_results(
        _resolv_query_tcp("bbc.com", 5, "8.8.8.8", _resolv_convert_query(DNS_MX))[1],
        "bbc.com"
    )
);

if (sizeof(array_diff($native, $resolv)) || sizeof(array_diff($resolv, $native))) {
    echo "Failed TCP check for bcc.com MX records\n";
    var_dump($native);
    var_dump($resolv);
    exit(1);
}

