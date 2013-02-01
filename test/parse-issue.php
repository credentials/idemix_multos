#!/usr/bin/php
<?php

$overhead = array();
$protocol = array();
$total = array();

for ($attr = 1; $attr <= 5; $attr++) {
  $file = fopen("run-" . $attr . "cred-0.6-sle78.log", 'r');

  $overhead["$attr"] = 0;
  $protocol["$attr"] = 0;

  $line = fgets($file);
  while (strpos($line, "### Presenting") === false) {
    if (strpos($line, "C: 801") !== false) {
      $cmd = $line;
      $line = fgets($file); 
      list($d) = sscanf($line, " duration: %d ms");
      if (strpos($cmd, "C: 8016") !== false || 
          strpos($cmd, "C: 801903") !== false ||
          strpos($cmd, "C: 801A02") !== false) {
        $protocol["$attr"] += $d;
      } else {
        $overhead["$attr"] += $d;
      }
      $line = fgets($file);
    } else {
      $line = fgets($file); 
    }
  }

  fclose($file);

  $total["$attr"] = $overhead["$attr"] + $protocol["$attr"];
}

echo "Total: "; print_r($total);
echo "Protocol execution: "; print_r($protocol);
echo "Transfer overhead: "; print_r($overhead);

