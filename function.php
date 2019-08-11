<?php

class request{
    static function get(string $name){
        return self::input(INPUT_GET, $name);
    }


    static function post(string $name){
        return self::input(INPUT_POST, $name);
    }


    static function cookie(string $name){
        return self::input(INPUT_COOKIE, $name);
    }


    static function file(string $name) :array{ // ['name'=>,'type'=>,'tmp_name'=>,'error'=>,'size'=>]
        $return = [];
        $files  = $_FILES[$name];

        if(!is_array($files['error'])){
            return ($files['error'] === UPLOAD_ERR_NO_FILE) ? $return : $files;
        }

        for($i = 0; $i < count($files['error']); $i++){
            if($files['error'][$i] === UPLOAD_ERR_NO_FILE){
                continue;
            }
            foreach(array_keys($files) as $key){
                $return[$i][$key] = $files[$key][$i];
            }
        }
        return $return;
    }


    static function header(string $name){
        $name = strtoupper($name);
        $name = str_replace('-', '_', $name);
        $name = sprintf('HTTP_%s', $name);
        return self::input(INPUT_SERVER, $name);
    }


    static function method(){
        return self::input(INPUT_SERVER, 'REQUEST_METHOD');
    }


    static function url(){
        $http = filter_input(INPUT_SERVER, 'HTTPS', FILTER_VALIDATE_BOOLEAN) ? 'https' : 'http';
        $host = self::input(INPUT_SERVER, 'HTTP_HOST');
        $port = self::input(INPUT_SERVER, 'SERVER_PORT');
        $path = self::input(INPUT_SERVER, 'REQUEST_URI');

        $port = (($http === 'http' && $port == 80) or ($http === 'https' && $port == 443)) ? '' : sprintf(':%s', $port);

        return sprintf('%s://%s%s%s', $http, $host, $port, $path);
    }


    private static function input(int $type, string $name){
        $value = filter_input($type, $name);

        if($value === false){ //配列の場合
            return filter_input($type, $name, FILTER_DEFAULT, FILTER_REQUIRE_ARRAY);
        }
        return $value;
    }
}


class response{
    static function redirect(string $url) :void{
        header("Location: $url");
        exit;
    }


    static function text(string $str) :void{
        header('Content-Type: text/plain; charset=utf-8');
        print $str;
        exit;
    }


    static function json($value, array $origin = []) :void{
        $json   = json_encode($value, JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_PARTIAL_OUTPUT_ON_ERROR);
        $origin = ($origin) ? implode(' ', $origin) : '*';

        header("Access-Control-Allow-Origin: $origin");
        header('Access-Control-Allow-Credentials: true');
        header('Content-Type: application/json; charset=utf-8');
        print $json;
        exit;
    }


    static function basic(callable $fn, string $realm = 'member only'){
        if(isset($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'])){
            if($fn($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW']) === true){
                return $_SERVER['PHP_AUTH_USER'];
            }
        }
        header('HTTP/1.0 401 Unauthorized');
        header("WWW-Authenticate: Basic realm='$realm'");
        return false;
    }
}


class fs{
    
}


class php{
    static function autoload(string $dir) :void{
        spl_autoload_register(function($class) use($dir){
            $class = explode('\\', $class);
            $class[count($class)-1] = ucfirst($class[count($class)-1]);
            $file = sprintf('%s/%s.php', $dir, implode('/', $class));

            if(file_exists($file)){
                require_once($file);
            }
        });
    }


    static function async(string $file, $arg = null) :void{
        if(preg_match('/^WIN/', PHP_OS)){
            $script  = sprintf('$arg=stream_get_contents(STDIN);$arg=unserialize(base64_decode($arg));include(\'%s\');', $file);
            $command = sprintf('start /b php -r %s', escapeshellarg($script));
        }
        else{
            $script  = sprintf('$arg=stream_get_contents(STDIN);$arg=unserialize(base64_decode($arg));include("%s");', $file);
            $command = sprintf('nohup php -r %s > /dev/null &', escapeshellarg($script));
        }

        $process = popen($command, 'w');
        fputs($process, base64_encode(serialize($arg)));
        pclose($process);
    }
}
