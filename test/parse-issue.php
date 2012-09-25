#!/usr/bin/php
<?php

$overhead = array();
$protocol = array();
$totalsum = array();

//for ($total = 1; $total <= 5; $total++) {
//$file = fopen("uprove_contact_$total.txt", 'r');

for ($total = 2; $total <= 5; $total += 3) {
$file = fopen("run-" . $total . "cred-0.2-sle78.log", 'r');

$overhead["$total"] = 0;
$protocol["$total"] = 0;

$line = fgets($file);
while (strpos($line, "### Presenting") === false) {
  if (strpos($line, "C: 00A4") !== false) {
    $line = fgets($file); $line = fgets($file);

  } else if (strpos($line, "C: 00FF") !== false) {
    $line = fgets($file); $line = fgets($file);
    
  } else if (strpos($line, "C: 000D") !== false || strpos($line, "C: 001") !== false) {
    $line = fgets($file); 
    list($d) = sscanf($line, " duration: %d ms");
    $protocol["$total"] += $d;
    $line = fgets($file);

  } else if (strpos($line, "duration") !== false) {
    list($d) = sscanf($line, " duration: %d ms");
    $overhead["$total"] += $d;
    $line = fgets($file);
    
  } else {
    $line = fgets($file); 
  }
}

fclose($file);

$totalsum["$total"] = $overhead["$total"] + $protocol["$total"];
}

echo "Total: "; print_r($totalsum);
echo "Protocol execution: "; print_r($protocol);
echo "Transfer overhead: "; print_r($overhead);


