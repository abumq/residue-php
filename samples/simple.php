<?php
include_once ("../src/residue.php");

$logger = \muflihun\Residue::instance("client.conf.json");

$logger->set_logger("sample-app"); // defaults to 'default' logger

function call() {
    global $logger;
    $logger->debug("test");
}

$logger->debug("another");

call();
