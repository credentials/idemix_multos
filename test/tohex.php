<?php

$file = fopen("input.txt", "r");

while ($line = fgets($file)) {
	print $line;
	if (is_numeric(trim($line))) {
		print exec("./tohex $line") . "\n";
	} 
}

fclose($file);
