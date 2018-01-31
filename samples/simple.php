<?php
include_once ("../src/residue.php");

$logger = Residue::instance("client.conf.json");

$logger->info("test");
