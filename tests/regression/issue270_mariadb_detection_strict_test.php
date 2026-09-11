<?php

$setup = file_get_contents(dirname(__DIR__, 2) . '/setup.php');

if ($setup === false) {
	fwrite(STDERR, "Failed to load setup.php\n");
	exit(1);
}

$legacyPattern = '/stripos\s*\(\s*\$database\s*\[\s*[\'"]{1}Value[\'"]{1}\s*\]\s*,\s*[\'"]{1}mariadb[\'"]{1}\s*\)\s*==\s*false/';
$fixedPattern  = '/stripos\s*\(\s*\$database\s*\[\s*[\'"]{1}Value[\'"]{1}\s*\]\s*,\s*[\'"]{1}mariadb[\'"]{1}\s*\)\s*===\s*false/';

if (preg_match($legacyPattern, $setup)) {
	fwrite(STDERR, "Legacy loose MariaDB stripos comparison is still present.\n");
	exit(1);
}

if (!preg_match($fixedPattern, $setup)) {
	fwrite(STDERR, "Strict MariaDB stripos comparison is missing.\n");
	exit(1);
}

print "issue270_mariadb_detection_strict_test passed\n";
