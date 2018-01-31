<?php

//
// Official PHP client library for Residue logging server
//
// Copyright 2017-present Muflihun Labs
//
// Author: @abumusamq
//
// https://muflihun.com
// https://muflihun.github.io/residue
// https://github.com/muflihun/residue-php
//

class ResidueInternalLogger 
{
    public static function err($msg)
    {
        echo "ERR: $msg\n";
    }
}

class Residue 
{
    protected static $_instance;

    public static function instance($config_file = null)
    {
        if (!(self::$_instance instanceof self)) {
            self::$_instance = new self();
            if ($config_file !== null) {
                self::$_instance->init($config_file);
            }
        }
        return self::$_instance;
    }

    public static function destroy()
    {
        self::$_instance = null;
    }

	private function __construct()
	{

    }

    private function init($config_file)
    {
        $this->config_file = $config_file;
        $this->config = json_decode(file_get_contents($config_file));
        if (!file_exists($this->config->session_dir)) {
            if (!mkdir($this->config->session_dir , 0777, true)) {
                ResidueInternalLogger::err("[{$this->config->session_dir}] is not writable");
                return false;
            }
        } else if (!is_writable($this->config->session_dir)) {
            ResidueInternalLogger::err("[{$this->config->session_dir}] is not writable");
            return false;
        }

        $this->config->host = substr($this->config->url, 0, strpos($this->config->url, ":"));
        $this->config->port = intval(substr($this->config->url, strpos($this->config->url, ":") + 1));

        $this->config->private_key_file = $this->config->session_dir . "/rsa.priv.pem";
        $this->config->public_key_file = $this->config->session_dir . "/rsa.pub.pem";
        $this->config->connection_file = $this->config->session_dir . "/conn";
        $this->config->tokens_dir = $this->config->session_dir . "/tokens/";

        if (!file_exists($this->config->tokens_dir)) {
            if (!mkdir($this->config->tokens_dir , 0777, true)) {
                ResidueInternalLogger::err("Failed to create directory [{$this->config->tokens_dir}]");
                return false;
            }
        } else if (!is_writable($this->config->tokens_dir)) {
            ResidueInternalLogger::err("[{$this->config->tokens_dir}] is not writable");
            return false;
        }

        $this->connect();

        return true;
    }

    private function buildReq($req_obj, $is_b64 = false)
    {
        $enc = json_encode($req_obj);
        if ($is_b64) {
            $enc = base64_encode($enc);
        }
        return $enc . "\r\n\r\n";
    }

    private function update_connection()
    {
        $this->connection = json_decode(file_get_contents($this->config->connection_file));
    }

    private function decrypt($enc, $method = 1) // 1 = AES ; 2 = RSA
    {
        switch ($method) {
            case 1:
                return shell_exec("echo '$enc' | {$this->config->ripe_bin} -d --key {$this->connection->key} --base64");
            case 2:
                $client_secret_param = "";
                if (!empty($this->config->client_key_secret)) {
                   $client_secret_param = " --secret {$this->config->client_key_secret} ";
                }
                return shell_exec("echo '$enc' | {$this->config->ripe_bin} -d --rsa --clean --in-key {$this->config->private_key_file} $client_secret_param --base64");
                break;
            default:
                return null;
        }
    }

    private function build_ripe()
    {
        return "{$this->config->ripe_bin} -e --key {$this->connection->key} --client-id {$this->connection->client_id}";
    }

    private function build_nc()
    {
        return "{$this->config->nc_bin} {$this->config->host} {$this->config->port}";
    }

    private function build_nc_token()
    {
        return "{$this->config->nc_bin} {$this->config->host} {$this->connection->token_port}";
    }

    private function build_nc_logging()
    {
        return "{$this->config->nc_bin} {$this->config->host} {$this->connection->logging_port}";
    }

    private function build_ripe_nc()
    {
        return "{$this->build_ripe()} | {$this->build_nc()}";
    }

    private function build_ripe_nc_token()
    {
        return "{$this->build_ripe()} | {$this->build_nc_token()}";
    }

    private function build_ripe_nc_logging()
    {
        return "{$this->build_ripe()} | {$this->build_nc_logging()}";
    }

    private function connect()
    {
        $this->connected = false;
        $this->connection = null;

        $req = array(
            "type" => 1 // CONNECT
        );
        $private_key_contents = "";
        if (empty($this->config->client_id) || empty($this->config->client_private_key)) {
            // generate RSA key
        } else {
            $req["client_id"] = $this->config->client_id;
            $private_key_contents = file_get_contents($this->config->client_private_key);
        }

        // save private key
        file_put_contents($this->config->private_key_file, $private_key_contents);

        $request = $this->buildReq($req);

        $server_encrypt_param = "";
        if (!empty($this->config->server_public_key)) {
            $server_encrypt_param = " | {$this->config->ripe_bin} -e --rsa --in-key {$this->config->server_public_key} ";
        }

        $result = shell_exec("printf \"`echo '$request' $server_encrypt_param`\r\n\r\n\" | {$this->build_nc()}");

        $plain_json = json_decode($result);
        if ($plain_json !== null) {
            ResidueInternalLogger::err("{$plain_json->error_text}, status: {$plain_json->status}");
            return false;
        }
        file_put_contents($this->config->connection_file, $this->decrypt($result, 2));
        $this->update_connection();
        
        // acknowledge
        $req = array(
            "client_id" => $this->connection->client_id,
            "type" => 2 // ACK
        );
        $request = $this->buildReq($req);
        $result = shell_exec("echo '$request' | {$this->build_ripe_nc()}");
        $plain_json = json_decode($result);
        if ($plain_json !== null) {
            ResidueInternalLogger::err("{$plain_json->error_text}, status: {$plain_json->status}");
            return false;
        }
        file_put_contents($this->config->connection_file, $this->decrypt($result));

        $this->update_connection();

        // verify
        $this->connected = $this->connection->status === 0 && $this->connection->ack === 1;
    }

    private function obtain_token($logger_id, $access_code)
    {
        $req = array(
            "logger_id" => $logger_id,
            "access_code" => $access_code
        );
        $request = $this->buildReq($req);
        $result = shell_exec("echo '$request' | {$this->build_ripe_nc_token()}");
        $decrypted_result = $this->decrypt($result);
        $decoded = json_decode($decrypted_result);
        if ($decoded !== null && !empty($decoded->error_text)) {
            ResidueInternalLogger::err("{$decoded->error_text}, status: {$decoded->status}");
            return false;
        }
        file_put_contents($this->config->tokens_dir . $logger_id, $decrypted_result);
    }

    // ------- Logging functions ---------

    public function info($msg)
    {
        $this->obtain_token("sample-app", "a2dcb");
        echo $msg . "\n";
    }
}
