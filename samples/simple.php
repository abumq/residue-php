<?php
include_once ("../src/residue.php");

\residue\Residue::init("client.conf.json");

$logger = new \residue\Logger("sample-app");

function call() {
    global $logger;
    $logger->debug("test");
}

$logger->debug("another");

call();

