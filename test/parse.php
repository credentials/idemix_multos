#!/usr/bin/php
<?php

$overhead = array();
$protocol = array();
$totalsum = array();

for ($total = 2; $total <= 5; $total += 3) {

$file = fopen("run-" . $total . "cred-0.2-sle78.log", 'r');

// Skip the issuing part
$line = fgets($file);
$i = 1;
while (strpos($line,"### Presenting") === false) {
  $line = fgets($file);
  $i++;
}
echo "Skipped issuing @ line $i: '$line'\n";

$attr = 0;
$overhead["$total"] = array();
$protocol["$total"] = array();
$line = fgets($file);

while (strpos($line, "completed successfully") === false) {
  if (strpos($line, "### Disclosing") !== false) {
    list($attr) = sscanf($line, "### Disclosing %d attributes");
    echo "Processing for number of attributes: $attr\n";
    $line = fgets($file);
    $attr = "$attr";
    
  } else if (strpos($line, "Proof Specification") !== false) {
    $line = fgets($file);
    
    while (strpos($line, "### Disclosing") === false && strpos($line, "Proof Specification") === false && strpos($line, "completed successfully") === false) {
      if (strpos($line, "C: 00A4") !== false) {
        $line = fgets($file); $line = fgets($file);

      } else if (strpos($line, "C: 0021") !== false) {
        $line = fgets($file); 
        list($d) = sscanf($line, " duration: %d ms");
        $protocol["$total"]["$attr"] += $d;
        $line = fgets($file);

      } else if (strpos($line, "duration") !== false) {
        list($d) = sscanf($line, " duration: %d ms");
        $overhead["$total"]["$attr"] += $d;
        $line = fgets($file);
    
      } else {
        $line = fgets($file); 
      }
    }
    
  } else {
    $line = fgets($file); 
  }
}

echo "File parsed\n";

fclose($file);

foreach ($protocol["$total"] as $key => $value) {
  $totalsum["$total"]["$key"] = $protocol["$total"]["$key"] + $overhead["$total"]["$key"];
}

foreach ($protocol["$total"] as $key => $value) {
  $protocol["$total"][$key] = $value / 50.0;
}

foreach ($overhead["$total"] as $key => $value) {
  $overhead["$total"][$key] = $value / 50.0;
}

foreach ($totalsum["$total"] as $key => $value) {
  $totalsum["$total"][$key] = $value / 50.0;
}

}

echo "Total: "; print_r($totalsum);
echo "Proof generation: "; print_r($protocol);
echo "Transfer overhead: "; print_r($overhead);

echo "\n\nTotal:\n";
echo "  &  0  &  1  &  2  &  3  &  4  &  5  \\\hline\n";
for ($i = 1; $i <= count($totalsum); $i++) {
  echo $i;
  for ($j = 0; $j < count($totalsum["$i"]); $j++) {
    printf(" & %3d", $totalsum["$i"]["$j"]);
  }
  echo " \\\hline\n";
}

echo "\n\nProof generation:\n";
echo "  &  0  &  1  &  2  &  3  &  4  &  5  \\\hline\n";
for ($i = 1; $i <= count($protocol); $i++) {
  echo $i;
  for ($j = 0; $j < count($protocol["$i"]); $j++) {
    printf(" & %3d", $protocol["$i"]["$j"]);
  }
  echo " \\\hline\n";
}

echo "\n\nTransfer overhead:\n";
echo "  &  0  &  1  &  2  &  3  &  4  &  5  \\\hline\n";
for ($i = 1; $i <= count($overhead); $i++) {
  echo $i;
  for ($j = 0; $j < count($overhead["$i"]); $j++) {
    printf(" & %3d", $overhead["$i"]["$j"]);
  }
  echo " \\\hline\n";
}

