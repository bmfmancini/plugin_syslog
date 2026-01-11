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

if (read_config_option('syslog_collector_enabled') !== 'on') {
    echo "Syslog Receiver is disabled in settings. Exiting.\n";
    exit(0);
}

$port = read_config_option('syslog_collector_port') ?: 514;
$interface = read_config_option('syslog_collector_interface') ?: '0.0.0.0';
$debug = false;


$batch_size = 100;        // Number of messages to buffer before bulk insert
$flush_interval = 5;      // Seconds between forced flushes
$message_buffer = array();
$last_flush_time = time();
$stats_messages_received = 0;
$stats_messages_inserted = 0;
$stats_last_report = time();

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
			case '--batch-size':
			case '-b':
				if (intval($value) > 0) {
					$batch_size = intval($value);
				}
				break;
			case '--flush-interval':
			case '-f':
				if (intval($value) > 0) {
					$flush_interval = intval($value);
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

if (read_config_option('syslog_collector_port') === '') {
    cacti_log('syslog_receiver.php: Syslog collector port is not set, defaulting to 514', false, 'syslog');
    if ($debug) {
        echo "syslog_receiver.php: Syslog collector port is not set in settings, defaulting to 514\n";
    }
}
if (read_config_option('syslog_collector_interface') === '') {
    cacti_log('syslog_receiver.php: Syslog collector interface is not set, defaulting to 0.0.0.0', false, 'syslog');
    if ($debug) {
        echo "syslog_receiver.php: Syslog collector interface is not set in settings, defaulting to 0.0.0.0\n";
    }
}


echo "Starting PHP Syslog Receiver on {$interface}:{$port} (UDP)\n";
cacti_log("Starting PHP Syslog Receiver on {$interface}:{$port} (UDP)", false, 'syslog');

$uri = "udp://{$interface}:{$port}";
$errno = 0; $errstr = '';
$sock = @stream_socket_server($uri, $errno, $errstr, STREAM_SERVER_BIND);
if (!$sock) {
    fwrite(STDERR, "ERROR: Failed to bind to {$uri} - {$errstr}\n");
    cacti_log("ERROR: Failed to bind to {$uri} - {$errstr}", false, 'syslog');
    exit(1);
}

echo "Syslog Receiver is now listening and ready to accept messages\n";
cacti_log("Syslog Receiver ready - Batch size: {$batch_size}, Flush interval: {$flush_interval}s", false, 'syslog');

while (true) {
    $peer = null;
    $data = @stream_socket_recvfrom($sock, 8192, 0, $peer);
    
    // Check if we should flush based on time interval
    $current_time = time();
    if (($current_time - $last_flush_time) >= $flush_interval && count($message_buffer) > 0) {
        flush_message_buffer($message_buffer, $stats_messages_inserted, $debug);
        $last_flush_time = $current_time;
    }
    
    // Report statistics every 60 seconds
    if (($current_time - $stats_last_report) >= 60) {
        $rate = $stats_messages_received / 60;
        echo sprintf("Stats: Received=%d, Inserted=%d, Rate=%.1f msg/sec\n", 
            $stats_messages_received, $stats_messages_inserted, $rate);
        cacti_log(sprintf("Stats: Received=%d, Inserted=%d, Rate=%.1f msg/sec", 
            $stats_messages_received, $stats_messages_inserted, $rate), false, 'syslog');
        $stats_messages_received = 0;
        $stats_messages_inserted = 0;
        $stats_last_report = $current_time;
    }
    
    if ($data === false || $data === '') {
        usleep(10000);
        continue;
    }

    $raw = trim($data);
    $logtime = date('Y-m-d H:i:s');

    if ($debug) {
        echo "RAW: " . substr($raw, 0, 500) . "\n";
    }

    // Parse the syslog message
    $parsed = parse_syslog_message($raw, $peer, $logtime);

    // Add message to buffer instead of immediate insert
    $message_buffer[] = $parsed;
    
    $stats_messages_received++;
    
    if ($debug) {
        echo "[{$parsed['logtime']}] From={$parsed['host']} Prog={$parsed['program']} Fac=" . var_export($parsed['facility_id'], true) . 
             " Pri=" . var_export($parsed['priority_id'], true) . " Msg=" . substr($parsed['message'], 0, 200) . 
             " [Buffered: " . count($message_buffer) . "]\n";
    }
    
    // Flush buffer when batch size is reached
    if (count($message_buffer) >= $batch_size) {
        flush_message_buffer($message_buffer, $stats_messages_inserted, $debug);
        $last_flush_time = time();
    }
}



/**
 * parse_syslog_message - parses a raw syslog message into components
 *
 * @param string $raw - raw syslog message data
 * @param string $peer - peer address (source IP)
 * @param string $logtime - timestamp for the message
 * @return array - parsed message components
 */
function parse_syslog_message($raw, $peer, $logtime) {
    $facility = null;
    $priority = null;
    $program = 'syslog';
    $host = null;
    $message = $raw;

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

    return array(
        'facility_id' => $facility,
        'priority_id' => $priority,
        'program' => $program,
        'logtime' => $logtime,
        'host' => $host,
        'message' => $message
    );
}

/**
 * flush_message_buffer - performs bulk insert of buffered messages
 *
 * @param array &$buffer - reference to message buffer array
 * @param int &$stats_inserted - reference to stats counter
 * @param bool $debug - debug mode flag
 * @return (void)
 */
function flush_message_buffer(&$buffer, &$stats_inserted, $debug = false) {
    global $syslogdb_default;
    
    if (empty($buffer)) {
        return;
    }
    
    $count = count($buffer);
    $start_time = microtime(true);
    
    try {
        // Build bulk INSERT statement
        $sql = "INSERT INTO `{$syslogdb_default}`.`syslog_incoming` " .
               '(facility_id, priority_id, program, logtime, host, message, status) VALUES ';
        
        $value_placeholders = array();
        $all_params = array();
        
        foreach ($buffer as $msg) {
            $value_placeholders[] = '(?, ?, ?, ?, ?, ?, 0)';
            $all_params[] = $msg['facility_id'];
            $all_params[] = $msg['priority_id'];
            $all_params[] = $msg['program'];
            $all_params[] = $msg['logtime'];
            $all_params[] = $msg['host'];
            $all_params[] = $msg['message'];
        }
        
        $sql .= implode(', ', $value_placeholders);
        
        syslog_db_execute_prepared($sql, $all_params);
        
        $elapsed = microtime(true) - $start_time;
        $stats_inserted += $count;
        
        if ($debug) {
            echo sprintf("FLUSH: Inserted %d messages in %.3f seconds (%.1f msg/sec)\n", 
                $count, $elapsed, $count / $elapsed);
        }
        
    } catch (Exception $e) {
        cacti_log("ERROR: Failed to flush message buffer ({$count} messages): " . $e->getMessage(), false, 'syslog');
        if ($debug) {
            echo "ERROR: Failed to flush buffer: " . $e->getMessage() . "\n";
        }
    }
    
    // Clear the buffer
    $buffer = array();
}

/**
 * display_help - displays help information
 *
 * @return (void)
 */
function display_help() {
	display_version();

	print 'The Syslog collector process script for Cacti Syslogging.' . PHP_EOL . PHP_EOL;
	print 'usage: syslog_collector.php [options]' . PHP_EOL . PHP_EOL;
	print 'options:' . PHP_EOL;
	print '  --port=PORT           Port number to listen on (default: 514).' . PHP_EOL;
	print '  --interface=IP        Interface IP to bind to (default: 0.0.0.0).' . PHP_EOL;
	print '  --batch-size=N        Number of messages to buffer before insert (default: 100).' . PHP_EOL;
	print '  --flush-interval=SEC  Seconds between forced buffer flushes (default: 5).' . PHP_EOL;
	print '  --debug               Provide more verbose debug output.' . PHP_EOL;
	print '  --version|-v          Display version information.' . PHP_EOL;
	print '  --help|-h             Display this help message.' . PHP_EOL . PHP_EOL;
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
	print 'Syslog Receiver, Version ' . trim($version['version']) . ', ' . COPYRIGHT_YEARS . PHP_EOL;
}

?>