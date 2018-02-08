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
// Version: 1.0.0
//

namespace residue_internal;

class InternalLogger 
{
    private static $verbose_level = 0;
    private static $new_line = PHP_EOL;

    public static function verbose($msg, $level)
    {
        if ($level <= InternalLogger::$verbose_level) {
            echo $msg;
            echo InternalLogger::$new_line;
        }
    }

    public static function err($msg)
    {
        InternalLogger::verbose($msg, 1);
    }

    public static function trace($msg)
    {
        InternalLogger::verbose("trace: " . $msg, 9);
    }

    public static function info($msg)
    {
        InternalLogger::verbose("info:  " . $msg, 2);
    }
}

abstract class LoggingLevel
{
    const Trace = 2;
    const Debug = 4;
    const Fatal = 8;
    const Error = 16;
    const Warning = 32;
    const Verbose = 64;
    const Info = 128;
}

abstract class Flag
{
    const NONE = 0;
    const ALLOW_UNKNOWN_LOGGERS = 1;
    const REQUIRES_TOKEN = 2;
    const ALLOW_DEFAULT_ACCESS_CODE = 4;
}

namespace residue;

class Residue 
{
    const TOUCH_THRESHOLD = 60;

    private $config_file = null;
    protected static $_instance;

    public static function init($config_file = null)
    {
        \residue_internal\InternalLogger::trace("init()");
        if (!(self::$_instance instanceof self)) {
            self::$_instance = new self();
            \residue_internal\InternalLogger::info("New residue instance");
            if ($config_file !== null) {
                self::$_instance->init_connection($config_file);
            }
        }
        \residue_internal\InternalLogger::info(self::$_instance === null ? "Residue: Null" : "Residue: Obj");
        return self::$_instance;
    }

    public static function destroy()
    {
        self::$_instance = null;
    }

    private function __construct()
    {
    }

    private function init_connection($config_file)
    {
        \residue_internal\InternalLogger::trace("init_connection()");
        $this->config_file = $config_file;
        $this->config = json_decode(file_get_contents($config_file));
        if (!file_exists($this->config->session_dir)) {
            if (!mkdir($this->config->session_dir , 0777, true)) {
                \residue_internal\InternalLogger::err("[{$this->config->session_dir}] is not writable");
                return false;
            }
        } else if (!is_writable($this->config->session_dir)) {
            \residue_internal\InternalLogger::err("[{$this->config->session_dir}] is not writable");
            return false;
        }

        $this->config->host = substr($this->config->url, 0, strpos($this->config->url, ":"));
        $this->config->port = intval(substr($this->config->url, strpos($this->config->url, ":") + 1));

        $this->config->private_key_file = $this->config->session_dir . "/rsa.priv.pem";
        $this->config->public_key_file = $this->config->session_dir . "/rsa.pub.pem";
        $this->config->connection_file = $this->config->session_dir . "/conn";
        $this->config->connection_mtime_file = $this->config->session_dir . "/conn.mtime";
        $this->config->tokens_dir = $this->config->session_dir . "/tokens/";
        $this->config->connection_lock_file = $this->config->session_dir . "/conn.lock";
        
        $sleepingFor = 0;
        while ($this->locked()) {
            sleep(1);
            if ($sleepingFor++ >= 5) {
                \residue_internal\InternalLogger::info("Unlocking manually");
                $this->unlock();
            }
        }

        // connection reset
        if (file_exists($this->config->connection_mtime_file) && file_exists($this->config->connection_file)) {
            $mt = intval(file_get_contents($this->config->connection_mtime_file));
            $age = $this->now() - $mt;
            if ($age >= $this->config->reset_conn) {
                \residue_internal\InternalLogger::info("Resetting connection");
                unlink($this->config->connection_file);
                unlink($this->config->connection_mtime_file);
                $this->delete_all_tokens();
            } else {
                $diff = $this->config->reset_conn - $age;
                \residue_internal\InternalLogger::info("Connection reset in {$diff}s (Age: {$age}s)");
            }
        }

        if (!file_exists($this->config->tokens_dir)) {
            if (!mkdir($this->config->tokens_dir , 0777, true)) {
                \residue_internal\InternalLogger::err("Failed to create directory [{$this->config->tokens_dir}]");
                return false;
            }
        } else if (!is_writable($this->config->tokens_dir)) {
            \residue_internal\InternalLogger::err("[{$this->config->tokens_dir}] is not writable");
            return false;
        }

        $this->update_connection();
        if (!$this->validate_connection()) {
            $this->connect();
        } else {
            $this->tokens = array();
            $this->connected = $this->connection->status === 0 && $this->connection->ack === 1;
        }
        \residue_internal\InternalLogger::info($this->connected === true ? "Successfully connected" : "Failed to connect");

        return true;
    }

    private function locked()
    {
        return file_exists($this->config->connection_lock_file);
    }

    private function unlock()
    {
        if ($this->locked()) {
            unlink($this->config->connection_lock_file);
        }
    }

    private function lock()
    {
        touch($this->config->connection_lock_file);
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
        if (file_exists($this->config->connection_file)) {
            $this->connection = json_decode(file_get_contents($this->config->connection_file));
        } else {
            $this->connection = null;
        }
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

    private function has_flag($f)
    {
        if ($this->connection === null) {
            return false;
        }
        return ($this->connection->flags & $f) !== 0;
    }

    private function reset()
    {
        $this->connected = false;
        $this->connection = null;
        $this->tokens = array();
    }

    private function connect()
    {
        $this->lock();
        \residue_internal\InternalLogger::trace("connect()");
        $this->reset();

        $req = array(
            "_t" => $this->now(),
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
            \residue_internal\InternalLogger::err("{$plain_json->error_text}, status: {$plain_json->status}");
            $this->unlock();
            return false;
        }
        file_put_contents($this->config->connection_file, $this->decrypt($result, 2));
        file_put_contents($this->config->connection_mtime_file, $this->now());
        $this->update_connection();
        
        // acknowledge
        $req = array(
            "_t" => $this->now(),
            "client_id" => $this->connection->client_id,
            "type" => 2 // ACK
        );
        $request = $this->buildReq($req);
        $result = shell_exec("echo '$request' | {$this->build_ripe_nc()}");
        $plain_json = json_decode($result);
        if ($plain_json !== null) {
            \residue_internal\InternalLogger::err("{$plain_json->error_text}, status: {$plain_json->status}");
            $this->unlock();
            return false;
        }
        file_put_contents($this->config->connection_file, $this->decrypt($result));
        file_put_contents($this->config->connection_mtime_file, $this->now());

        $this->update_connection();

        $this->delete_all_tokens();

        // verify
        $this->connected = $this->connection->status === 0 && $this->connection->ack === 1;
        $this->unlock();
    }

    private function delete_all_tokens()
    {
        \residue_internal\InternalLogger::trace("delete_all_tokens()");
        if (file_exists($this->config->tokens_dir)) {
            array_map('unlink', glob("{$this->config->tokens_dir}/*"));
        }
    }

    private function touch()
    {
        \residue_internal\InternalLogger::trace("touch()");
        $this->lock();
        if (!$this->connected) {
            $this->connect();
            $this->unlock();
            return false;
        }

        $req = array(
            "_t" => $this->now(),
            "client_id" => $this->connection->client_id,
            "type" => 3
        );
        $request = $this->buildReq($req);
        $result = shell_exec("echo '$request' | {$this->build_ripe_nc()}");
        $decrypted_result = $this->decrypt($result);
        $decoded = json_decode($decrypted_result);
        if ($decoded !== null && !empty($decoded->error_text)) {
            \residue_internal\InternalLogger::err("{$decoded->error_text}, status: {$decoded->status}");
            $this->unlock();
            return false;
        }
        file_put_contents($this->config->connection_file, $decrypted_result);
        $this->update_connection();
        $this->delete_all_tokens();

        $this->connected = $this->connection->status === 0 && $this->connection->ack === 1;
        $this->unlock();
        return true;
    }

    private function validate_connection()
    {
        \residue_internal\InternalLogger::trace("validate_connection()");
        if ($this->connection === null) {
            return false;
        }
        return $this->connection->age === 0 || $this->connection->date_created + $this->connection->age >= $this->now();
    }

    private function should_touch()
    {
        \residue_internal\InternalLogger::trace("should_touch()");
        if ($this->connection === null || $this->connection->age === 0) {
            return false;
        }
        return $this->connection->age - ($this->now() - $this->connection->date_created) < Residue::TOUCH_THRESHOLD;
    }

    private function now()
    {
        return time();
    }

    private function validate_token($token)
    {
        \residue_internal\InternalLogger::trace("validate_token()");
        if (!$this->has_flag(\residue_internal\Flag::REQUIRES_TOKEN)) {
            \residue_internal\InternalLogger::info("no token required");
            return true;
        }
        return $token !== null && ($token->life === 0 || $this->now() - $token->date_created < $token->life);
    }

    private function obtain_token($logger_id, $access_code)
    {
        $this->lock();
        \residue_internal\InternalLogger::trace("obtain_token()");
        $req = array(
            "_t" => $this->now(),
            "logger_id" => $logger_id,
            "access_code" => $access_code
        );
        $request = $this->buildReq($req);
        $result = shell_exec("echo '$request' | {$this->build_ripe_nc_token()}");
        $decrypted_result = $this->decrypt($result);
        $decoded = json_decode($decrypted_result);
        if ($decoded !== null && !empty($decoded->error_text)) {
            \residue_internal\InternalLogger::err("{$decoded->error_text}, status: {$decoded->status}");
            $this->unlock();
            return false;
        }
        $decoded->date_created = $this->now();
        $final = json_encode($decoded);
        file_put_contents($this->config->tokens_dir . $logger_id, $final);
        $this->update_token($logger_id);
        $this->unlock();
    }

    private function update_token($logger_id)
    {
        \residue_internal\InternalLogger::trace("update_token()");
        $this->tokens[$logger_id] = null;
        if (file_exists($this->config->tokens_dir . $logger_id)) {
            $token_info = json_decode(file_get_contents($this->config->tokens_dir . $logger_id));
            $this->tokens[$logger_id] = json_decode(json_encode(array(
                "token" => $token_info->token, 
                "life" => $token_info->life, 
                "date_created" => $token_info->date_created
            )));
        }
    }

    private function read_access_code($logger_id)
    {
        \residue_internal\InternalLogger::trace("read_access_code()");
        foreach ($this->config->access_codes as &$ac) {
            if ($ac->logger_id === $logger_id) {
                return $ac->code;
            }
        }
        return null;
    }
    
    public function build_thread_id()
    {
        if (isset($_SERVER)) {
            if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
                return $_SERVER['HTTP_CLIENT_IP'];
            }
            if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
                return $_SERVER['HTTP_X_FORWARDED_FOR'];
            }
            if (!empty($_SERVER['REMOVE_ADDR'])) {
                return $_SERVER['REMOTE_ADDR'];
	    }
        }
        return "";
    }

    private function write_log_internal($logger_id, $msg, $level, $vlevel = 0)
    {
        \residue_internal\InternalLogger::trace("write_log()");
        if (!$this->connected) {
            \residue_internal\InternalLogger::info("no connection");
            $this->connect();
        }
        if (!$this->validate_connection()) {
            \residue_internal\InternalLogger::info("connection expired");
            $this->connected = false;
            $this->connect();
        }
        if ($this->should_touch()) {
            \residue_internal\InternalLogger::info("connection should be touched");
            $this->touch();
        }
        if ($this->has_flag(\residue_internal\Flag::REQUIRES_TOKEN)) {
            if (array_key_exists($logger_id, $this->tokens)) {
                if (!$this->validate_token($this->tokens[$logger_id])) {
                    \residue_internal\InternalLogger::info("token expired (memory)");
                    $this->obtain_token($logger_id, $this->read_access_code($logger_id));
                }
            } else {
                $this->update_token($logger_id);
                if (!$this->validate_token($this->tokens[$logger_id])) {
                    \residue_internal\InternalLogger::info("token expired");
                    $this->obtain_token($logger_id, $this->read_access_code($logger_id));
                }
            }
        }
        $debug_trace = debug_backtrace();
        $req = array(
            "_t" => $this->now(),
            "datetime" => $this->now() * 1000,
            "logger" => $logger_id,
            "msg" => $msg,
            "app" => $this->config->application_id,
            "level" => $level,
            "file" => $debug_trace[2]["file"],
            "line" => $debug_trace[2]["line"],            
            "func" => count($debug_trace) > 3 ? $debug_trace[3]["function"] : ""
        );
        if ($this->config->time_offset > 0) {
            $req["datetime"] = $req["datetime"] + (1000 * $this->config->time_offset);
        }
        if ($this->has_flag(\residue_internal\Flag::REQUIRES_TOKEN)) {
            $req["token"] = $this->tokens[$logger_id]->token;
        }
        if ($vlevel > 0) {
            $req["vlevel"] = $vlevel;
        }
        $thread_id = $this->build_thread_id();
        if (!empty($thread_id)) {
            $req["thread"] = $thread_id;
        }
        $request = $this->buildReq($req);
        $result = shell_exec("echo '$request' | {$this->build_ripe_nc_logging()} > /dev/null 2>/dev/null &");
    }
    
    private function to_string_by_type($o)
    {
        switch (gettype($o)) {
        case "boolean":
            return $o ? "TRUE" : "FALSE";
        case "array":
            return json_encode($o);
        case "NULL":
            return "NULL";
        case "string":
            return $o;
        case "integer":
        case "double":
            return (string)$o;
        case "object":
            return method_exists($o, '__toString') ? (string) $o : serialize($o);
        case "resource":
        default:
            return serialize($o);
        }
    }

    public function write_log($logger_id, $level, $vlevel, $format, ...$values)
    {
        $final_msg = "";
        switch (gettype($format)) {
        case "string":
            foreach ($values as &$v) {
                $v = $this->to_string_by_type($v);
            }
            $final_msg = sprintf($format, ...$values);
            break;
        default:
            $final_msg = $this->to_string_by_type($format);
            break;
        }
        $this->write_log_internal($logger_id, $final_msg, $level, $vlevel);
    }

    public function initialised()
    {
        return $this->config_file !== null;
    }
}

class Logger
{
    private $logger_id = "default";
    private $residue_instance = null;
    private $is_ready = false;

    public function __construct($logger_id = "default")
    {
        \residue_internal\InternalLogger::trace("new Logger()");

        $this->logger_id = $logger_id;

        $residue_instance = Residue::init();

        if ($residue_instance->initialised()) {
            $this->residue_instance = $residue_instance;
            $this->is_ready = true;
        } else {
            \residue_internal\InternalLogger::err("Residue not initialised. You must initialise the residue instance before you can use ResidueLogger");
        }
    }

    public function info($format, ...$values)
    {
        if (!$this->is_ready) return;
        $this->residue_instance->write_log($this->logger_id, \residue_internal\LoggingLevel::Info, 0, $format, ...$values);
    }

    public function warning($format, ...$values)
    {
        if (!$this->is_ready) return;
        $this->residue_instance->write_log($this->logger_id, \residue_internal\LoggingLevel::Warning, 0, $format, ...$values);
    }

    public function error($format, ...$values)
    {
        if (!$this->is_ready) return;
        $this->residue_instance->write_log($this->logger_id, \residue_internal\LoggingLevel::Error, 0, $format, ...$values);
    }

    public function debug($format, ...$values)
    {
        if (!$this->is_ready) return;
        $this->residue_instance->write_log($this->logger_id, \residue_internal\LoggingLevel::Debug, 0, $format, ...$values);
    }

    public function fatal($format, ...$values)
    {
        if (!$this->is_ready) return;
        $this->residue_instance->write_log($this->logger_id, \residue_internal\LoggingLevel::Fatal, 0, $format, ...$values);
    }

    public function trace($format, ...$values)
    {
        if (!$this->is_ready) return;
        $this->residue_instance->write_log($this->logger_id, \residue_internal\LoggingLevel::Trace, 0, $format, ...$values);
    }

    public function verbose($vlevel, $format, ...$values)
    {
        if (!$this->is_ready) return;
        $this->residue_instance->write_log($this->logger_id, \residue_internal\LoggingLevel::Verbose, $vlevel, $format, ...$values);
    }
}
