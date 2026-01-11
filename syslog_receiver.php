<?php

/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2025 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU General Public License             |
 | as published by the Free Software Foundation; either version 2          |
 | of the License, or (at your option) any later version.                  |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU General Public License for more details.                            |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDTool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
 | This code is designed, written, and maintained by the Cacti Group. See  |
 | about.php and/or the AUTHORS file for specific developer information.   |
 +-------------------------------------------------------------------------+
 | http://www.cacti.net/                                                   |
 +-------------------------------------------------------------------------+
*/


include(dirname(__FILE__) . '/../../include/cli_check.php');
include_once(dirname(__FILE__) . '/functions.php');
include_once(dirname(__FILE__) . '/database.php');
syslog_connect();

// defaults
$opts = getopt('', array('udp::','tcp::','port::','interface::','debug','help'));
$use_udp = true;
$port = isset($opts['port']) && intval($opts['port']) ? intval($opts['port']) : 514;
$interface = isset($opts['interface']) ? $opts['interface'] : '0.0.0.0';
$debug = isset($opts['debug']);

ini_set('memory_limit', '-1');
set_time_limit(0);



/* process calling arguments */
$parms = $_SERVER['argv'];
array_shift($parms);

if (cacti_sizeof($parms)) {
	foreach($parms as $parameter) {
		if (strpos($parameter, '=')) {
			list($arg, $value) = explode('=', $parameter);
		} else {
			$arg = $parameter;
			$value = '';
		}

		switch ($arg) {
			case '--debug':
			case '-d':
				$debug = true;

				break;
            case '--protocol':
            case '-p':
                if (strtolower($value) === 'tcp') {
                    $use_udp = false;
                } else {
                    $use_udp = true;
                }
                break;
            case '--port':
            case '-P':
                if (intval($value)) {
                    $port = intval($value);
                }
                break;
            case '--interface':
            case '-i':
                if (!empty($value)) {
                    $interface = $value;
                }
                break;
			case '--version':
			case '-V':
			case '-v':
				display_version();
				exit;
			case '--help':
			case '-H':
			case '-h':
				display_help();
				exit;
			default:
				print "ERROR: Invalid Argument: ($arg)\n\n";
				display_help();
				exit(1);
		}
	}
}



echo "Starting PHP Syslog Receiver on {$interface}:{$port} (UDP)\n";

$uri = "udp://{$interface}:{$port}";
$errno = 0; $errstr = '';
$sock = @stream_socket_server($uri, $errno, $errstr, STREAM_SERVER_BIND);
if (!$sock) {
    fwrite(STDERR, "ERROR: Failed to bind to {$uri} - {$errstr}\n");
    exit(1);
}

while (true) {
    $peer = null;
    $data = @stream_socket_recvfrom($sock, 8192, 0, $peer);
    if ($data === false || $data === '') {
        usleep(100000);
        continue;
    }

    $raw = trim($data);
    $logtime = date('Y-m-d H:i:s');
    $facility = null;
    $priority = null;
    $program = 'syslog';
    $host = null;
    $message = $raw;

    if ($debug) {
        echo "RAW: " . substr($raw,0,500) . "\n";
    }

    // Extract PRI (facility and priority) per RFC 3164/5424
    // Format: <PRI>remainder where PRI = facility * 8 + priority
    if (preg_match('/^<(\d+)>(.*)$/s', $raw, $m)) {
        $pri = intval($m[1]);
        $facility = intdiv($pri, 8);
        $priority = $pri % 8;
        $message = trim($m[2]);
    }

    // Try to extract program name from standard RFC format: "program:" or "program[pid]:"
    // This is the TAG field per RFC 3164 - alphanumeric with optional [pid]
    if (preg_match('/^(?:\S+\s+\S+\s+\S+\s+)?(?:\S+\s+)?([a-zA-Z0-9_\-\.]+)(?:\[\d+\])?:\s*(.*)$/s', $message, $m)) {
        $program = $m[1];
        // Don't modify $message - keep it as the full payload after PRI
    } else {
        $program = 'syslog';
    }

    // Host is always the source IP (peer) - this is most reliable per RFC
    if (!empty($peer)) {
        $peer_addr = preg_replace('/^[a-z]+:\/\//i', '', $peer);
        if (preg_match('/^\[?([^\]]+)\]?:\d+$/', $peer_addr, $pm)) {
            $host = $pm[1];
        } else {
            $host = preg_replace('/:\d+$/', '', $peer_addr);
        }
    }

    // Final fallbacks
    if (empty($host)) {
        $host = 'unknown';
    }
    if (empty($program)) {
        $program = 'syslog';
    }

    // Prepare insert
    global $syslogdb_default;
    $sql = 'INSERT INTO `' . $syslogdb_default . '`.`syslog_incoming` (facility_id, priority_id, program, logtime, host, message, status) VALUES (?, ?, ?, ?, ?, ?, 0)';
    $params = array($facility, $priority, $program, $logtime, $host, $message);

    $ok = syslog_db_execute_prepared($sql, $params);
    if ($debug) {
        echo "[{$logtime}] From={$host} Prog={$program} Fac=" . var_export($facility, true) . " Pri=" . var_export($priority, true) . " Msg=" . substr($message,0,200) . "\n";
    }
}



/**
 * display_help - displays help information
 *
 * @return (void)
 */
function display_help() {
	display_version();

	print 'The main Syslog poller process script for Cacti Syslogging.' . PHP_EOL . PHP_EOL;
	print 'usage: syslog_process.php [--debug] [--force-report]' . PHP_EOL . PHP_EOL;
	print 'options:' . PHP_EOL;
    print '  --protocol=udp|tcp   Protocol to listen on (default: udp).' . PHP_EOL;
    print '  --port=PORT          Port number to listen on (default: 514).' . PHP_EOL;
    print '  --interface=IP       Interface IP to bind to (default:0.0.0.0).' . PHP_EOL;
	print '    --debug          Provide more verbose debug output.' . PHP_EOL . PHP_EOL;
}


/**
 * display_version - displays version information
 *
 * @return (void)
 */
function display_version() {
	global $config;

	if (!function_exists('plugin_syslog_version')) {
		include_once($config['base_path'] . '/plugins/syslog/setup.php');
	}

	$version = plugin_syslog_version();
	print 'Syslog Poller, Version ' . trim($version['version']) . ', ' . COPYRIGHT_YEARS . PHP_EOL;
}

?>