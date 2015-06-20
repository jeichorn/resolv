<?php

use LibDNS\Messages\MessageFactory;
use LibDNS\Messages\MessageTypes;
use LibDNS\Records\QuestionFactory;
use LibDNS\Records\ResourceQTypes;
use LibDNS\Encoder\EncoderFactory;
use LibDNS\Decoder\DecoderFactory;


// @TODO: this interface needs to change and allow for specifying what
// record type we need as it might be necessary for testing. For example
// dns_get_record() doesn't return any SPF records at all so we can't do
// a direct comparison of the below vs dns_get_record(.., DNS_ALL);

/**
 * Retrieve all DNS records for a given host, with 5 seconds as the default
 * timeout for the operation, using Google's public nameservers.
 */
function resolv_get_records($host, $query = DNS_ALL, $timeout = 5.0, $ns = null)
{
    if (is_null($query)) {
        $query = DNS_ALL;
    }

    $query = _resolv_convert_query($query);

    if (is_null($ns)) {
        $ns = '8.8.8.8';
    }

    try {
        $start = microtime(true);

        $res = _resolv_choice([
            function() use ($host, $query, &$timeout, $ns) {
                return call_user_func_array("_resolv_query_udp", [$host, $timeout, $ns, $query]);
            },
            // this is merely to update the timeout to reflect the time we
            // spent in the function above
            function() use ($start, &$timeout) {
                $timeout -= (microtime(true) - $start);
                return [false, null];
            },
            function() use ($host, $query, &$timeout, $ns) {
                return call_user_func_array("_resolv_query_tcp", [$host, $query, $ns, $query]);
            }
        ]);

        if (is_null($res)) {
            throw new Exception("Unable to fetch records");
        }

        // Handle response
        if ($res->getResponseCode() !== 0) {
            throw new Exception("Server returned error code " . $res->getResponseCode());
        }

        return _resolv_convert_results($res, $host);
    } catch (Exception $e) {
        return [];
    }
}

function _resolv_build_request_packet($host, $query = ResourceQTypes::ALL)
{
    $question = (new QuestionFactory)->create($query);
    $question->setName($host);

    // Create request message
    $request = (new MessageFactory)->create(MessageTypes::QUERY);
    $request->getQuestionRecords()->add($question);
    $request->isRecursionDesired(true);

    // Encode request message
    $encoder = (new EncoderFactory)->create();
    return $encoder->encode($request);
}

/**
 * Extract the number of seconds and microseconds from a float.
 */
function _resolv_calculate_timeout($timeout)
{
    $sec  = floor($timeout);
    $usec = round(($timeout - floor($timeout)) * 1000000);
    return [$sec, $usec];
}

function _resolv_query_udp($host, $timeout, $ns, $query = ResourceQTypes::ALL)
{
    $requestPacket = _resolv_build_request_packet($host, $query);
    // Send request
    $socket = stream_socket_client("udp://$ns:53");
    stream_socket_sendto($socket, $requestPacket);
    $r = [$socket];
    $w = $e = [];

    list($sec, $usec) = _resolv_calculate_timeout($timeout);

    if (!stream_select($r, $w, $e, $sec, $usec)) {
        throw new Exception("Request timeout");
    }

    // Decode response message
    $decoder = (new DecoderFactory)->create();
    $responsePacket = fread($socket, 512);
    $response = $decoder->decode($responsePacket);
    fclose($socket);
    return [!$response->isTruncated(), $response];
}

function _resolv_query_tcp($host, $timeout, $ns, $query = ResourceQTypes::ALL)
{
    $requestPacket = _resolv_build_request_packet($host, $query);
    $socket = stream_socket_client("tcp://$ns:53");

    socket_set_blocking($socket, 1);

    $r = $e = [];
    $w = [$socket];

    list($sec, $usec) = _resolv_calculate_timeout($timeout);

    if (!stream_select($r, $w, $e, $sec, $usec)) {
        throw new Exception("Request timeout");
    }

    $l = strlen($requestPacket);
    $s = chr($l >> 8) . chr($l);

    fwrite($socket, $s);
    fwrite($socket, $requestPacket);

    $w = $e = [];
    $r = [$socket];

    if (!stream_select($r, $w, $e, $sec, $usec)) {
        throw new Exception("Request timeout");
    }

    if (($data = fread($socket, 2)) === false || strlen($data) != 2) {
        throw new Exception("Can't read response from the server");
    }

    $length = ord($data[0]) << 8 | ord($data[1]);

    $chunk = '';
    $chunk_size = $length;
    socket_set_blocking($socket, 0);
    $data = '';

    while (1) {
        $chunk = fread($socket, $chunk_size);
        if ($chunk === false) {
            throw new Exception("Failed reading data from the socket");
        }

        $data .= $chunk;

        $chunk_size -= strlen($chunk);
        if (strlen($data) >= $length) {
            break;
        }
    }

    fclose($socket);
    $decoder = (new DecoderFactory)->create();
    $response = $decoder->decode($data);
    return [true, $response];
}

/**
 * Take a list of functions and return the results of  the first one that
 * succeeds. Each function should return a list of two elements, with the first
 * one being a boolean indicating success/failure, and the second one containing
 * the result.
 */
function _resolv_choice($fns)
{
    $res = null;

    foreach ($fns as $fn) {
        list($success, $res) = $fn();
        if ($success) {
            break;
        }
    }

    return $res;
}

function _resolv_convert_query($query)
{
    switch ($query) {
        case DNS_ALL: return ResourceQTypes::ALL;
        case DNS_A: return ResourceQTypes::A;
        case DNS_NS: return ResourceQTypes::NS;
        case DNS_CNAME: return ResourceQTypes::CNAME;
        case DNS_SOA: return ResourceQTypes::SOA;
        case DNS_PTR: return ResourceQTypes::PTR;
        case DNS_HINFO: return ResourceQTypes::HINFO;
        case DNS_MX: return ResourceQTypes::MX;
        case DNS_TXT: return ResourceQTypes::TXT;
        case DNS_A6: return ResourceQTypes::A6;
        case DNS_SRV: return ResourceQTypes::SRV;
        case DNS_NAPTR: return ResourceQTypes::NAPTR;
        case DNS_AAAA: return ResourceQTypes::AAAA;
        case DNS_ANY: return ResourceQTypes::ALL;
        default: throw new Exception("Unknown query {$query}");
    }
}

/**
 * Converts a record returned by LibDNS to a format compatible with the
 * built-in dns_get_record() function. Currently only adds extra information
 * to records lookup_domain() is specifically interested in.
 */
function _resolv_convert_libdns_record($record, $host)
{
    $r          = [];
    $r["host"]  = $host;
    $r["class"] = "IN";
    $r["type"]  = _resolv_get_record_type($record->getType());
    $r["ttl"]   = $record->getTTL();

    switch ($record->getType()) {
        case ResourceQTypes::A:
            $r["ip"] = $record->getData()
                ->getFieldByName("address")
                ->getValue();
            break;
        case ResourceQTypes::MX:
            list($r["pri"], $r["target"]) = [
                $record->getData()
                    ->getFieldByName("preference")
                    ->getValue(),
                $record->getData()
                    ->getFieldByName("exchange")
                    ->getValue()];
            break;
        case ResourceQTypes::CNAME:
            $r["target"] =
                $record->getData()
                    ->getFieldByName("cname")
                    ->getValue();
            break;
        case ResourceQTypes::NS:
            $r["target"] = $record->getData()
                ->getFieldByName("nsdname")
                ->getValue();
            break;
        case ResourceQTypes::PTR:
            $r["target"] = $record->getData()
                ->getFieldByName("ptrdname")
                ->getValue();
            break;
        case ResourceQTypes::TXT:
            $r["txt"] = $record->getData()
                ->getFieldByName("txtdata")
                ->getValue();
            break;
        case ResourceQTypes::HINFO: {
            $r["cpu"] = $record->getData()
                ->getFieldByName("cpu")
                ->getValue();
            $r["os"] = $record->getData()
                ->getFieldByName("os")
                ->getValue();
            break;
        }
        case ResourceQTypes::SOA: {
            $r["mname"] = $record->getData()
                ->getFieldByName("mname")
                ->getValue();
            $r["rname"] = $record->getData()
                ->getFieldByName("rname")
                ->getValue();
            $r["serial"] = $record->getData()
                ->getFieldByName("serial")
                ->getValue();
            $r["refresh"] = $record->getData()
                ->getFieldByName("refresh")
                ->getValue();
            $r["retry"] = $record->getData()
                ->getFieldByName("retry")
                ->getValue();
            $r["expire"] = $record->getData()
                ->getFieldByName("expire")
                ->getValue();
            $r["minimum-ttl"] = $record->getData()
                ->getFieldByName("minimum")
                ->getValue();
            break;
        }
        case ResourceQTypes::AAAA:
            $r["ipv6"] = $record->getData()
                ->getFieldByName("address")
                ->getValue();
            break;
        // @TODO: no A6
        case ResourceQTypes::SRV: {
            $r["prio"] = $record->getData()
                ->getFieldByName("priority")
                ->getValue();
            $r["weight"] = $record->getData()
                ->getFieldByName("weight")
                ->getValue();
            $r["target"] = $record->getData()
                ->getFieldByName("name")
                ->getValue();
            $r["port"] = $record->getData()
                ->getFieldByName("port")
                ->getValue();
            break;
        }
        case ResourceQTypes::NAPTR: {
            $r["order"] = $record->getData()
                ->getFieldByName("order")
                ->getValue();
            $r["pref"] = $record->getData()
                ->getFieldByName("preference")
                ->getValue();
            $r["flags"] = $record->getData()
                ->getFieldByName("flags")
                ->getValue();
            $r["services"] = $record->getData()
                ->getFieldByName("services")
                ->getValue();
            $r["regexp"] = $record->getData()
                ->getFieldByName("regexp")
                ->getValue();
            $r["replacement"] = $record->getData()
                ->getFieldByName("replacement")
                ->getValue();
            break;
        }
    }

    return $r;
}

function _resolv_get_record_type($type)
{
    $types = _libdns_record_types();

    if (isset($types[$type])) {
        return $types[$type];
    } else {
        return "unknown";
    }
}

function _libdns_record_types()
{
    return [
        ResourceQTypes::A          => "A",
        ResourceQTypes::AAAA       => "AAAA",
        ResourceQTypes::AFSDB      => "AFSDB",
        ResourceQTypes::CAA        => "CAA",
        ResourceQTypes::CERT       => "CERT",
        ResourceQTypes::CNAME      => "CNAME",
        ResourceQTypes::DHCID      => "DHCID",
        ResourceQTypes::DLV        => "DLV",
        ResourceQTypes::DNAME      => "DNAME",
        ResourceQTypes::DNSKEY     => "DNSKEY",
        ResourceQTypes::DS         => "DS",
        ResourceQTypes::HINFO      => "HINFO",
        ResourceQTypes::KEY        => "KEY",
        ResourceQTypes::KX         => "KX",
        ResourceQTypes::ISDN       => "ISDN",
        ResourceQTypes::LOC        => "LOC",
        ResourceQTypes::MB         => "MB",
        ResourceQTypes::MD         => "MD",
        ResourceQTypes::MF         => "MF",
        ResourceQTypes::MG         => "MG",
        ResourceQTypes::MINFO      => "MINFO",
        ResourceQTypes::MR         => "MR",
        ResourceQTypes::MX         => "MX",
        ResourceQTypes::NAPTR      => "NAPTR",
        ResourceQTypes::NS         => "NS",
        ResourceQTypes::NULL       => "NULL",
        ResourceQTypes::PTR        => "PTR",
        ResourceQTypes::RP         => "RP",
        ResourceQTypes::RT         => "RT",
        ResourceQTypes::SIG        => "SIG",
        ResourceQTypes::SOA        => "SOA",
        ResourceQTypes::SPF        => "SPF",
        ResourceQTypes::SRV        => "SRV",
        ResourceQTypes::TXT        => "TXT",
        ResourceQTypes::WKS        => "WKS",
        ResourceQTypes::X25        => "X25"
    ];
}

function _resolv_convert_results($res, $host)
{
    $records = [];

    foreach ($res->getAnswerRecords() as $ar) {
        $records[] = _resolv_convert_libdns_record($ar, $host);
    }

    return $records;
}