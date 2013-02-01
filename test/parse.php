#!/usr/bin/php
<?php

$overhead = array();
$protocol = array();
$total = array();
$count = array();

for ($attr = 1; $attr <= 5; $attr++) {
  $file = fopen("run-" . $attr . "cred-0.6-sle78.log", 'r');

  // Skip the issuing part
  $line = fgets($file);
  while (strpos($line,"### Presenting") === false) {
    $line = fgets($file);
  }

  $disclosed = 0;
  $overhead["$attr"] = array();
  $protocol["$attr"] = array();
  $total["$attr"] = array();
  $count["$attr"] = array();
  
  $line = fgets($file);
  while (strpos($line, "completed successfully") === false) {
    if (strpos($line, "### Disclosing") !== false) {
      list($disclosed) = sscanf($line, "### Disclosing %d attributes");
      echo "Processing for number of attributes: $disclosed\n";
      $disclosed = "$disclosed";
      $count["$attr"]["$disclosed"] += 1;
      
      $line = fgets($file);
      while (strpos($line, "### Disclosing") === false && strpos($line, "completed successfully") === false) {
        if (strpos($line, "C: 802") !== false) {
	  $cmd = $line;
          $line = fgets($file);
          list($d) = sscanf($line, " duration: %d ms");
	  if (strpos($cmd, "C: 8022") !== false) {
            $protocol["$attr"]["$disclosed"] += $d;
	  } else {
            $overhead["$attr"]["$disclosed"] += $d;
          }
          $line = fgets($file);
        } else {
          $line = fgets($file); 
        }
      }
    
    } else {
      $line = fgets($file); 
    }
  }

  fclose($file);

  foreach ($protocol["$attr"] as $key => $value) {
    $total["$attr"]["$key"] = $protocol["$attr"]["$key"] + $overhead["$attr"]["$key"];
  }

  foreach ($protocol["$attr"] as $key => $value) {
    $protocol["$attr"][$key] = $value / ($count["$attr"]["$key"] * 1.0);
  }

  foreach ($overhead["$attr"] as $key => $value) {
    $overhead["$attr"][$key] = $value / ($count["$attr"]["$key"] * 1.0);
  }

  foreach ($total["$attr"] as $key => $value) {
    $total["$attr"][$key] = $value / ($count["$attr"]["$key"] * 1.0);
  }
}

echo "Total: "; print_r($total);
echo "Count: "; print_r($count);
echo "Proof generation: "; print_r($protocol);
echo "Transfer overhead: "; print_r($overhead);

echo "\n\nTotal:\n";
echo "  &  0  &  1  &  2  &  3  &  4  &  5  \\\hline\n";
for ($i = 1; $i <= count($total); $i++) {
  $attr = $i + 1;
  echo $attr;
  for ($j = 0; $j < count($total["$attr"]); $j++) {
    printf(" & %3d", $total["$attr"]["$j"]);
  }
  echo " \\\hline\n";
}

echo "\n\nProof generation:\n";
echo "  &  0  &  1  &  2  &  3  &  4  &  5  \\\hline\n";
for ($i = 1; $i <= count($protocol); $i++) {
  $attr = $i + 1;
  echo $attr;
  for ($j = 0; $j < count($protocol["$attr"]); $j++) {
    printf(" & %3d", $protocol["$attr"]["$j"]);
  }
  echo " \\\hline\n";
}

echo "\n\nTransfer overhead:\n";
echo "  &  0  &  1  &  2  &  3  &  4  &  5  \\\hline\n";
for ($i = 1; $i <= count($overhead); $i++) {
  $attr = $i + 1;
  echo $attr;
  for ($j = 0; $j < count($overhead["$attr"]); $j++) {
    printf(" & %3d", $overhead["$attr"]["$j"]);
  }
  echo " \\\hline\n";
}

