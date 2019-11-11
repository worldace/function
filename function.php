<?php
// https://spelunker2.wordpress.com/2019/08/26/function-php/


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


    static function query(){
        return self::input(INPUT_SERVER, 'QUERY_STRING');
    }


    static function time(){
        return $_SERVER['REQUEST_TIME'];
    }


    static function header(string $name){
        $name = strtoupper($name);
        $name = str_replace('-', '_', $name);
        $name = sprintf('HTTP_%s', $name);
        return filter_input(INPUT_SERVER, $name);
    }


    static function method(){
        return filter_input(INPUT_SERVER, 'REQUEST_METHOD');
    }


    static function is_get() :bool{
        return filter_input(INPUT_SERVER, 'REQUEST_METHOD') === 'GET';
    }


    static function is_post() :bool{
        return filter_input(INPUT_SERVER, 'REQUEST_METHOD') === 'POST';
    }


    static function url(){
        $http = filter_input(INPUT_SERVER, 'HTTPS', FILTER_VALIDATE_BOOLEAN) ? 'https' : 'http';
        $host = filter_input(INPUT_SERVER, 'HTTP_HOST');
        $port = filter_input(INPUT_SERVER, 'SERVER_PORT');
        $path = filter_input(INPUT_SERVER, 'REQUEST_URI');

        $port = (($http === 'http' && $port == 80) or ($http === 'https' && $port == 443)) ? '' : sprintf(':%s', $port);

        return sprintf('%s://%s%s%s', $http, $host, $port, $path);
    }


    static function file(string $name) :array{
        $files = $_FILES[$name] ?? ['name'=>'', 'type'=>'' ,'tmp_name'=>'' ,'error'=>UPLOAD_ERR_NO_FILE, 'size'=>0];

        if(!is_array($files['name'])){
            return $files;
        }

        for($i = 0; $i < count($files['name']); $i++){
            foreach(array_keys($files) as $key){
                $return[$i][$key] = $files[$key][$i];
            }
        }
        return $return;
    }


    static function upload(string $name, string $dir, array $whitelist = ['jpg','jpeg','png','gif']) :array{
        $files = self::file($name);

        if(isset($files['name'])){ //single
            $files['file'] = self::upload_move($files, $dir, $whitelist);
        }
        else if($files){
             foreach($files as $k => $v){
                 $files[$k]['file'] = self::upload_move($v, $dir, $whitelist);
             }
        }
        return $files;
    }


    private static function upload_move(array $files, string $dir, array $whitelist){
        $extention = pathinfo($files['name'], PATHINFO_EXTENSION); //拡張子なしは空文字列
        $extention = strtolower($extention);

        if($files['error'] === UPLOAD_ERR_NO_FILE){
            return;
        }
        if($files['error'] !== UPLOAD_ERR_OK || !in_array($extention, $whitelist, true)){
            return false;
        }
    
        $savepath = sprintf('%s/%s.%s', $dir, uniqid(bin2hex(random_bytes(2))), $extention);
        return (move_uploaded_file($files['tmp_name'], $savepath)) ? realpath($savepath) : false;
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


    static function download(string $file, string $name, int $timeout = 60*60*6) :void{
        ini_set('max_execution_time', $timeout);

        $size = preg_match('/^data:.*?,/', $file, $m) ? (strlen($file) - strlen($m[0])) : filesize($file);
        $name = str_replace(['"',"'","\r","\n"], '', $name);
        $utf8 = rawurlencode($name);

        header("Content-Type: application/force-download");
        header("Content-Length: $size");
        header("Content-Disposition: attachment; filename='$name'; filename*=UTF-8''$utf8");

        while(ob_get_level()){
            ob_end_clean();
        }
        readfile($file);
    }


    static function basic(callable $fn, string $realm = 'members only'){
        if(isset($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'])){
            if($fn($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW']) === true){
                return $_SERVER['PHP_AUTH_USER'];
            }
        }
        header('HTTP/1.0 401 Unauthorized');
        header("WWW-Authenticate: Basic realm='$realm'");
        return false;
    }


    static function nocache(){
        header('Cache-Control: no-store');
    }
}



class str{
    static function file(?string $str){
        return 'data:,' . $str;
    }


    static function match(?string $str, string $needle) :bool{
        return mb_strpos($str, $needle) !== false;
    }


    static function match_start(?string $str, string $needle) :bool{
        return mb_substr($str, 0, mb_strlen($needle)) === $needle;
    }


    static function match_end(?string $str, string $needle) :bool{
        return mb_substr($str, -mb_strlen($needle)) === $needle;
    }


    static function shift(?string $str, string $needle){
        $result = mb_strstr($str, $needle, true);
        return ($result !== false) ? $result : $str;
    }


    static function pop(?string $str, string $needle){
        $result = mb_substr(mb_strrchr($str, $needle), 1);
        return ($result !== false) ? $result : '';
    }


    static function replace_once(?string $str, string $needle, string $replace) :string{
        $needle = preg_quote($needle, '/');
        return preg_replace("/$needle/u", $replace, $str, 1);
    }


    static function insert_before(?string $str, string $needle, string $insert) :string{
        $pos = mb_strpos($str, $needle);
        return ($pos !== false) ? preg_replace("/^.{0,$pos}+\K/us", $insert, $str) : $str;
    }


    static function insert_after(?string $str, string $needle, string $insert) :string{
        $pos = mb_strpos($str, $needle) + mb_strlen($needle);
        return ($pos !== false) ? preg_replace("/^.{0,$pos}+\K/us", $insert, $str) : $str;
    }


    static function remove_bom(?string $str) :string{
        return ltrim($str, "\xEF\xBB\xBF");
    }


    static function split_all(?string $str) :array{
        return preg_split('//u', $str, 0, PREG_SPLIT_NO_EMPTY);
    }


    static function template(?string $str, array $table) :string{
        return preg_replace_callback('/{{(.+?)}}/', function($m) use($table){ return $table[$m[1]]; }, $str);
    }


    static function base64_encode_urlsafe(?string $str) :string{
        return rtrim(strtr(base64_encode($str), '+/', '-_'), '=');
    }


    static function base64_decode_urlsafe(?string $str) :string{
        return base64_decode(strtr($str, '-_', '+/'));
    }


    static function base_encode($value, int $base = 62) :string{
        $chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $str = '';

        do{
            $mem   = bcmod($value, $base);
            $str   = $chars[$mem] . $str;
            $value = bcdiv(bcsub($value, $mem), $base);
        } while(bccomp($value,0) > 0);

        return $str;
    }


    static function base_decode(string $str, int $base = 62) :string{
        $chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $arr   = array_flip(str_split($chars));
        $len   = strlen($str);
        $val   = '0';

        for($i = 0;  $i < $len;  $i++){
            $val = bcadd($val, bcmul($arr[$str[$i]], bcpow($base, $len-$i-1)));
        }

        return $val;
    }


    static function f(string $format, ...$replace){
        return preg_replace_callback('/%(%|n|r|s|h|u|b|j)/', function($m) use(&$replace){
            if    ($m[0] === '%%'){ return '%'; }
            elseif($m[0] === '%n'){ return "\n"; }
            elseif($m[0] === '%r'){ return "\r"; }
            $v = array_shift($replace);
            if    ($m[0] === '%s'){ return $v; }
            elseif($m[0] === '%h'){ return htmlspecialchars($v, ENT_QUOTES, 'UTF-8', false); }
            elseif($m[0] === '%u'){ return rawurlencode($v); }
            elseif($m[0] === '%b'){ return base64_encode($v); }
            elseif($m[0] === '%j'){ return json_encode($v, JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_PARTIAL_OUTPUT_ON_ERROR); }
        }, $format);
    }
}



class html{
    static public $template_dir;

    static function e(?string $str) :string{
        return htmlspecialchars($str, ENT_QUOTES, 'UTF-8', false);
    }

    static function template($str){
        $heads = [];
        $bodys = [];

        $html = preg_replace_callback('/{{(.+?)}}/', function($m) use(&$heads, &$bodys){
            ob_start();
            include sprintf('%s/%s', html::$template_dir, $m[1]);
            if(isset($head)){
                $heads[$m[1]] = $head;
            }
            if(isset($body)){
                $bodys[$m[1]] = $body;
            }
            return ob_get_clean();
        }, $str);

        $html = str::insert_before($html, '</head>', implode("\n", $heads));
        $html = str::insert_before($html, '</body>', implode("\n", $bodys));
        return $html;
    }
}



class url{
    static function home(string $url) :string{
        $part = explode('/', $url);
        return sprintf('%s//%s/', $part[0], $part[2]);
    }


    static function dir(string $url) :string{
        $url = preg_replace('/\?.*/', '', $url);
        return (substr_count($url, '/') === 2) ? $url.'/' : dirname($url.'a').'/';
    }


    static function full(string $path, string $base_url) :string{
        
    }
}



class http{
    public static $header;

    static function get(string $url, array $query = [], array $request_header = []){
        if($query){
            $url .= (strpos($url, '?')) ? '&' : '?';
            $url .= http_build_query($query, '', '&', PHP_QUERY_RFC3986);
        }

        $return = file_get_contents($url, false, self::context('GET', $request_header));
        self::$header = $http_response_header;

        return $return;
    }


    static function post(string $url, array $query = [], array $request_header = []){
        $content = http_build_query($query, '', '&');

        $request_header += [
            'Content-Type'   => 'application/x-www-form-urlencoded; charset=UTF-8',
            'Content-Length' => strlen($content),
        ];

        $return = file_get_contents($url, false, self::context('POST', $request_header, $content));
        self::$header = $http_response_header;

        return $return;
    }


    static function post_file(string $url, array $query = [], array $request_header = []){
        $_ = sprintf('__%s__', sha1(uniqid()));
        $n = "\r\n";

        $content = '';
        foreach($query as $name => $value){
            $name = str_replace(['"', "\r", "\n"], '', $name);
            if(is_array($value)){
                foreach($value as $name2 => $value2){
                    $name2  = str_replace(['"', "\r", "\n"], '', $name2);
                    $value2 = is_resource($value2) ? stream_get_contents($value2) : file_get_contents($value2);
                    if($value2 === false){
                        continue;
                    }
                    $content .= sprintf('--%s%s', $_, $n);
                    $content .= sprintf('Content-Disposition: form-data; name="%s"; filename="%s"%s', $name, $name2, $n);
                    $content .= sprintf('Content-Type: %s%s%s', file::mime($name2), $n, $n);
                    $content .= sprintf('%s%s', $value2, $n);
                }
            }
            else{
                $content .= sprintf('--%s%s', $_, $n);
                $content .= sprintf('Content-Disposition: form-data; name="%s"%s%s', $name, $n, $n);
                $content .= sprintf('%s%s', $value, $n);
            }
        }
        $content .= sprintf('--%s--%s', $_, $n);

        $request_header += [
            'Content-Type'   => "multipart/form-data; boundary=$__",
            'Content-Length' => strlen($content),
        ];

        $return = file_get_contents($url, false, self::context('POST', $request_header, $content));
        self::$header = $http_response_header;

        return $return;
    }


    static function get_multi(array $url, int $parallel = 5, array $option = []) :array{
        $option += [ // http://php.net/manual/ja/function.curl-setopt.php
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => false,
        ];

        $mh = curl_multi_init();
        curl_multi_setopt($mh, CURLMOPT_PIPELINING, 1); // http://php.net/manual/ja/function.curl-multi-setopt.php
        curl_multi_setopt($mh, CURLMOPT_MAX_TOTAL_CONNECTIONS, $parallel);
        curl_multi_setopt($mh, CURLMOPT_MAX_HOST_CONNECTIONS, $parallel);

        foreach($url as $k => $v){
            $ch[$k] = curl_init($v);
            curl_setopt_array($ch[$k], $option);
            curl_multi_add_handle($mh, $ch[$k]);
        }

        do {
            curl_multi_exec($mh, $running);
            curl_multi_select($mh);
        } while ($running > 0);

        foreach($ch as $k => $v){
            //$info = curl_getinfo($ch[$key]); // http://php.net/manual/ja/function.curl-getinfo.php
            $return[$url[$k]] = curl_multi_getcontent($v);
            curl_multi_remove_handle($mh, $v);
        }

        curl_multi_close($mh);
        return $return ?? [];
    }


    private static function context(string $method, array $request_header, string $content = null){
        $header = '';
        foreach($request_header as $k => $v){
            $k = str_replace([':', "\r", "\n"], '', $k);
            $v = str_replace(["\r", "\n"], '', $v);
            $header .= sprintf('%s: %s%s', $k, $v, "\r\n");
        }

        $http['method']  = $method;
        $http['header']  = $header;
        $http['content'] = $content;

        return stream_context_create(['http'=>$http]);
    }
}


class arr{
    static function save(array $array, string $file){
        file_put_contents($file, sprintf('<?php return %s;', var_export($array,true)), LOCK_EX);
    }
}



class file{
    static function edit(string $file, callable $fn, ...$args){
        $fp = fopen($file, 'cb+');
        if(!$fp){
            return false;
        }
        flock($fp, LOCK_EX);

        while(($line = fgets($fp)) !== false){
            $contents[] = $line;
        }
        $contents = $fn($contents, ...$args);

        if(is_array($contents)){
            $contents = implode('', $contents);
        }

        if(is_string($contents)){
            ftruncate($fp, 0);
            rewind($fp);
            fwrite($fp, $contents);
            flock($fp, LOCK_UN);
            fclose($fp);
            return true;
        }
        else{
            flock($fp, LOCK_UN);
            fclose($fp);
            return false;
        }
    }


    static function edit_contents(string $file, callable $fn, ...$args){
        $fp = fopen($file, 'cb+');
        if(!$fp){
            return false;
        }
        flock($fp, LOCK_EX);

        $contents = $fn(stream_get_contents($fp), ...$args);

        if(is_string($contents)){
            ftruncate($fp, 0);
            rewind($fp);
            fwrite($fp, $contents);
            flock($fp, LOCK_UN);
            fclose($fp);
            return true;
        }
        else{
            flock($fp, LOCK_UN);
            fclose($fp);
            return false;
        }
    }


    static function permission(string $file, string $permission = null) :string{
        if(!preg_match('/^0/', $permission) and $permission >= 100 and $permission <= 777){
            chmod($file, octdec($permission));
        }
        return decoct(fileperms($file) & 0777);
    }


    static function list(string $dir, bool $recursive = true, string $base = '') :array{
       if($base === ''){ //初回
            $dir = realpath($dir);
            if(preg_match('/^WIN/', PHP_OS)){
                $dir = str_replace('\\', '/', $dir);
            }
            $base = $dir;
        }

        $return = [];
        foreach(array_diff(scandir($dir), ['.','..']) as $file){
            $path     = "$dir/$file";
            $relative = substr($path, strlen($base)+1);
            if(is_dir($path)){
                if($recursive){
                    $return = array_merge($return, self::list($path, true, $base));
                }
            }
            else{
                $return[$relative] = $path;
            }
        }

        return $return;
    }


    static function list_all(string $dir, bool $recursive = true, string $base = '') :array{
       if($base === ''){ //初回
            $dir = realpath($dir);
            if(preg_match('/^WIN/', PHP_OS)){
                $dir = str_replace('\\', '/', $dir);
            }
            $base = $dir;
        }

        $return = [];
        foreach(array_diff(scandir($dir), ['.','..']) as $file){
            $path     = "$dir/$file";
            $relative = substr($path, strlen($base)+1);
            if(is_dir($path)){
                $return[$relative.'/'] = $path.'/';
                if($recursive){
                    $return = array_merge($return, self::list_all($path, true, $base));
                }
            }
            else{
                $return[$relative] = $path;
            }
        }

        return $return;
    }


    static function mime(string $file) :string{ // http://www.iana.org/assignments/media-types/media-types.xhtml
        static $mime = [
            'jpg'  => 'image/jpeg',
            'jpeg' => 'image/jpeg',
            'png'  => 'image/png',
            'gif'  => 'image/gif',
            'bmp'  => 'image/bmp',
            'svg'  => 'image/svg+xml',
            'ico'  => 'image/x-icon',
            'txt'  => 'text/plain',
            'htm'  => 'text/html',
            'html' => 'text/html',
            'css'  => 'text/css',
            'xml'  => 'text/xml',
            'csv'  => 'text/csv',
            'tsv'  => 'text/tab-separated-values',
            'js'   => 'application/javascript',
            'json' => 'application/json',
            'doc'  => 'application/msword',
            'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'xls'  => 'application/vnd.ms-excel',
            'xlsx' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'ppt'  => 'application/vnd.ms-powerpoint',
            'pptx' => 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'pdf'  => 'application/pdf',
            'swf'  => 'application/x-shockwave-flash',
            'zip'  => 'application/zip',
            'lzh'  => 'application/x-lzh',
            'mp3'  => 'audio/mpeg',
            'wav'  => 'audio/x-wav',
            'wmv'  => 'video/x-ms-wmv',
            '3g2'  => 'video/3gpp2',
            'mp4'  => 'video/mp4',
        ];

        $extention = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        return $mime[$extention] ?? 'application/octet-stream';
    }
}



class dir{
    static function create(string $dir, string $permission = '755') :bool{
        $mask = umask();
        umask(0);
        $return = mkdir($dir, octdec($permission), true);
        umask($mask);
        return $return;
    }


    static function delete(string $dir) :bool{
        foreach(array_diff(scandir($dir), ['.','..']) as $file){
            is_dir("$dir/$file") ? self::delete("$dir/$file") : unlink("$dir/$file");
        }
        return rmdir($dir);
    }


    static function permission(string $dir, string $permission = null) :string{
        return file::permission($dir, $permission);
    }


    static function list(string $dir, bool $recursive = true, string $base = '') :array{
       if($base === ''){ //初回
            $dir = realpath($dir);
            if(preg_match('/^WIN/', PHP_OS)){
                $dir = str_replace('\\', '/', $dir);
            }
            $base = $dir;
        }

        $return = [];
        foreach(array_diff(scandir($dir), ['.','..']) as $file){
            $path     = "$dir/$file";
            $relative = substr($path, strlen($base)+1);
            if(is_dir($path)){
                $return[$relative.'/'] = $path.'/';
                if($recursive){
                    $return = array_merge($return, self::list($path, true, $base));
                }
            }
        }

        return $return;
    }

}



class xml{
    static function parse(string $xml, bool $is_array = false){
        $xml = trim($xml);
        $xml = preg_replace("/&(?!([a-zA-Z0-9]{2,8};)|(#[0-9]{2,5};)|(#x[a-fA-F0-9]{2,4};))/", "&amp;" , $xml);
        $SimpleXML = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOBLANKS|LIBXML_NOCDATA|LIBXML_NONET|LIBXML_COMPACT|LIBXML_PARSEHUGE);

        return ($is_array) ? json_decode(json_encode([$SimpleXML->getName()=>$SimpleXML]), true) : $SimpleXML;
    }
}



class csv{
    static function parse(string $str, array $option = []) :array{
        return iterator_to_array(self::file('data:,'.$str, $option));
    }


    static function file(string $file, array $option = []) :\Generator{
        $option += [
            'input'     => null,
            'output'    => null,
            'delimiter' => null,
            'escape'    => '"',
            'skip'      => 0,
        ];

        $fp = fopen($file, 'rb');
        $sample = fread($fp, 1024);
        rewind($fp);

        if(preg_match("/^\xEF\xBB\xBF/", $sample)){ //BOM検知
            $option['input'] = 'utf-8';
            fseek($fp, 3);
        }
        if(!$option['input'] and $option['output']){ //入力文字コード検知
            $option['input'] = mb_detect_encoding($sample, ['UTF-8', 'SJIS-WIN', 'EUCJP-WIN']);
        }
        if(!$option['delimiter']){ //区切り検知
            $option['delimiter'] = self::detect_delimiter($sample);
        }

        while(($csv = self::get_line($fp, $option['delimiter'], $option['escape'])) !== false){
            if($option['skip'] > 0){
                $option['skip']--;
                continue;
            }
            if($csv === ['']){
                $csv = [];
            }
            if($option['output']){
                mb_convert_variables($option['output'], $option['input'], $csv);
            }
            yield $csv;
        }
        fclose($fp);
    }


    static function create(iterable $csv, array $option = []) :string{
        $option += [
            'br'        => "\n",
            'enclose'   => true,
            'delimiter' => ',',
            'escape'    => '"',
        ];

        $return = '';
        foreach($csv as $line){
            $newline = [];
            foreach($line as $v){
                $v = preg_replace("/\r\n|\n|\r/", $option['br'], $v);
                if(strlen($v) and !is_numeric($v)){
                    $v = str_replace($option['escape'], $option['escape'].$option['escape'], $v);
                    $v = $option['escape'] . $v . $option['escape'];
                }
                $newline[] = $v;
            }
            $return .= implode($option['delimiter'], $newline) . "\r\n";
        }

        return $return;
    }


    private static function get_line($fp, $d = ',', $e = '"'){
        $d    = preg_quote($d);
        $e    = preg_quote($e);
        $line = '';

        while($fp and !feof($fp)){
            $line .= fgets($fp);
            if(preg_match_all("/$e/", $line) % 2 === 0){
                break;
            }
        }

        $count  = preg_match_all(sprintf('/(%s[^%s]*(?:%s%s[^%s]*)*%s|[^%s]*)%s/', $e,$e,$e,$e,$e,$e,$d,$d), preg_replace('/(?:\\r\\n|[\\r\\n])?$/', $d, rtrim($line)), $match);
        $return = $match[1];

        for($i = 0;  $i < $count;  $i++){
            $return[$i] = preg_replace(sprintf('/^%s(.*)%s$/s', $e,$e), '$1', $return[$i]);
            $return[$i] = str_replace("$e$e", $e, $return[$i]);
        }

        return empty($line) ? false : $return;
    }


    private static function detect_delimiter(string $sample){
        $count_c = substr_count($sample, ',');
        $count_t = substr_count($sample, "\t");
        return ($count_c >= $count_t) ? ',' : "\t";
    }
}



class zip{
    static function create(string $file, $dir){
        $zip = new \ZipArchive(); // http://php.net/ziparchive
        $zip->open($file, ZipArchive::CREATE);

        if(is_string($dir)){
            foreach(file::list_all($dir) as $k => $v){
                ($k[-1] === '/') ? $zip->addEmptyDir($k) : $zip->addFile($v, $k);
            }
        }
        else{
            foreach($dir as $k => $v){
                (is_resource($v)) ? $zip->addFromString($k, stream_get_contents($v)) : $zip->addFile($v, $k);
            }
        }
        $zip->close();
    }


    static function add(string $file, string $add, string $path){
        $zip = new \ZipArchive();
        $zip->open($file);

        is_resource($add) ? $zip->addFromString($path, stream_get_contents($add)) : $zip->addFile($add, $path);

        $zip->close();
    }


    static function unzip(string $file, string $target = ""){
        $zip = new \ZipArchive();
        $zip->open($file);

        $target  = ($target) ? realpath($target) : realpath(dirname($file));
        $target .= DIRECTORY_SEPARATOR;

        for($i = 0;  $i < $zip->numFiles;  $i++){
            $name = $zip->getNameIndex($i, ZipArchive::FL_ENC_RAW);

            //ファイル名のエンコードについて
            $encode = mb_detect_encoding($name, ['utf-8', 'sjis-win', 'eucjp']);
            if($encode !== 'UTF-8'){
                $name = mb_convert_encoding($name, 'utf-8', $encode);
            }

            //解凍先ディレクトリがないなら作る
            $dir = ($name[-1] === '/') ? $target.$name : $target.dirname($name);
            if(!is_dir($dir)){
                mkdir($dir, 0755, true);
            }

            if($name[-1] === '/'){
                continue;
            }
            if(file_put_contents($target.$name, $zip->getStream($zip->getNameIndex($i)), LOCK_EX) !== false){ // $zip->getFromIndex($i) という方法もあるけど
                $return[] = $target.$name;
            }
        }

        $zip->close();
        return $return ?? [];
    }
}



class is{
    static function int($v, int $min = 0, int $max = PHP_INT_MAX) :bool{
        return filter_var($v, FILTER_VALIDATE_INT, ['options'=>['min_range'=>$min, 'max_range'=>$max]]) !== false;
    }


    static function utf8($v) :bool{
        return preg_match('//u', $v);
    }


    static function nully($v) :bool{
        if($v === 0 || $v === "0"){
            return false;
        }
        return empty($v);
    }
}



class time{
    static function micro() :string{
        [$micro, $sec] = explode(' ', microtime());
        $micro = substr($micro, 2, 6);
        return $sec . $micro;
    }


    static function past(int $time) :string{
        $diff = time() - $time;

        switch($diff){
            case $diff < 1        : return '今';
            case $diff < 60       : return $diff.'秒前';
            case $diff < 3600     : return floor($diff/60).'分前';
            case $diff < 86400    : return floor($diff/3600).'時間前';
            case $diff < 2592000  : return floor($diff/86400).'日前';
            case $diff < 31536000 : return floor($diff/2592000).'ヶ月前';
            default               : return floor($diff/31536000).'年前';
        }
    }


    static function calendar(int $year = null, int $month = null) :array{
        $date = isset($year, $month) ? new \DateTime("$year-$month") : new \DateTime('first day of');

        $wday = $date->format('w');
        $days = $date->format('t');
        $week = 0;

        for($i = $wday; $i > 0; $i--){
            $return[$week][] = '';
        }

        for($i = 1; $i <= $days; $i++){
            if($wday > 6){
                $wday = 0;
                $week++;
            }
            $wday++;
            $return[$week][] = $i;
        }

        for($i = $wday; $i <= 6; $i++){
            $return[$week][] = '';
        }

        return $return;
    }
}



class random{
    static function id(){
        [$micro, $sec] = explode(' ', microtime());
        $micro = substr($micro, 2, 6);
        $rand  = mt_rand(1000, 5202); //5202より大きいと12桁になる
        return str::base_encode("$rand$micro$sec");
    }


    static function uuid(bool $hyphen = false) :string{ // http://php.net/manual/en/function.uniqid.php#94959
        $format = ($hyphen) ? '%04x%04x-%04x-%04x-%04x-%04x%04x%04x' : '%04x%04x%04x%04x%04x%04x%04x%04x';
        return sprintf($format, mt_rand(0,0xffff),mt_rand(0,0xffff), mt_rand(0,0xffff), mt_rand(0,0x0fff)|0x4000, mt_rand(0,0x3fff)|0x8000, mt_rand(0,0xffff),mt_rand(0,0xffff),mt_rand(0,0xffff));
    }


    static function str(int $length) :string{
        $chars  = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $max    = strlen($chars) - 1;
        $return = '';

        for($i = 0;  $i < $length;  $i++){
            $return .= $chars[mt_rand(0, $max)];
        }

        return $return;
    }


    static function crypt(string $str, string $password) :string{
        $iv = openssl_random_pseudo_bytes(16); // openssl_cipher_iv_length('aes-128-cbc') == 16
        return bin2hex($iv) . openssl_encrypt($str, 'aes-128-cbc', $password, 0, $iv); //先頭32バイトがiv
    }


    static function decrypt(string $str, string $password) :string{
        $iv = substr($str, 0, 32);
        return openssl_decrypt(substr($str, 32), 'aes-128-cbc', $password, 0, hex2bin($iv));
    }


    static function chance($chance) :bool{
        $chance = (float)$chance;

        if($chance <= 0){
            return false;
        }
        else if($chance >= 100){
            return true;
        }
        else{
            $i = mt_rand(1, round(100/$chance*100000));
            return $i <= 100000;
        }
    }
}



class jwt{
    static function encode(array $data, string $password, string $algorithm = 'HS256'){
        $head64 = str::base64_encode_urlsafe(json_encode(['typ'=>'jwt', 'alg'=>$algorithm]));
        $data64 = str::base64_encode_urlsafe(json_encode($data));

        if($algorithm === 'HS256'){
            $sign = hash_hmac('sha256', "$head64.$data64", $password, true);
        }
        elseif($algorithm === 'RS256'){
            openssl_sign("$head64.$data64", $sign, $password, 'sha256');
        }

        return sprintf('%s.%s.%s', $head64, $data64, str::base64_encode_urlsafe($sign));
    }


    static function decode(string $jwt, string $return_type = 'data'){
        [$head64, $data64, $sign64] = explode('.', $jwt);

        if($return_type === 'data'){
            return json_decode(str::base64_decode_urlsafe($data64), true);
        }
        else if($return_type === 'head'){
            return json_decode(str::base64_decode_urlsafe($head64), true);
        }
        else if($return_type === 'sign'){
            return str::base64_decode_urlsafe($sign64);
        }
    }


    static function verify(string $jwt, $password, string $algorithm = 'HS256') :bool{
        [$head64, $data64, $sign64] = explode('.', $jwt);
        $sign = str::base64_decode_urlsafe($sign64);

        if($algorithm === 'HS256' and $sign === hash_hmac('sha256', "$head64.$data64", $password, true)){
            return true;
        }
        else if($algorithm === 'RS256' and openssl_verify("$head64.$data64", $sign, $password, 'sha256') === 1){
            return true;
        }
        return false;
    }
}



class page{
    static function number(int $page_number, int $count_all, int $count_per_page) :array{
        $page['prev'] = ($page_number > 1) ? $page_number - 1 : null;
        $page['next'] = ($count_all > $page_number * $count_per_page) ? $page_number + 1 : null;
        return $page;
    }
}



class php{
    static function go(string $file, $arg = null, ...$files) :void{
        array_unshift($files, $file);

        foreach($files as $_v){
            $_arg = (function() use($arg, $_v){
                return require($_v);
            })();
            if(isset($_arg)){
                $arg = $_arg;
            }
        }

        exit;
    }


    static function autoload(string $dir) :void{
        spl_autoload_register(function($class) use($dir){
            $path = str_replace('\\', '/', $class);
            $file = sprintf('%s/%s.php', $dir, $path);

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


    static function function_toString($fn) :string{
        $ref = (is_string($fn) and strpos($fn, '::')) ? new \ReflectionMethod($fn) : new \ReflectionFunction($fn);

        $return = implode('', array_slice(file($ref->getFileName()), $ref->getStartLine()-1, $ref->getEndLine()-$ref->getStartLine()+1));
        $return = preg_replace("/^.*(function[\s|\(])/i", '$1', $return);
        $return = preg_replace("/}.*$/", "}", $return);

        return $return;
    }


    static function class_toString(string $class) :string{
        $ref = new \ReflectionClass($class);

        $return = implode('', array_slice(file($ref->getFileName()), $ref->getStartLine()-1, $ref->getEndLine()-$ref->getStartLine()+1));
        $return = preg_replace("/^.*(class[\s|\(|\{])/i", '$1', $return);
        $return = preg_replace("/}.*$/", "}", $return);

        return $return;
    }


    function benchmark(callable $fn, ...$args){
        $start = microtime(true);
        $end   = $start + 1;

        if($args){
            for($count = -1;  microtime(true) <= $end;  $count++){
                $fn(...$args);
            }
        }
        else{
            for($count = -1;  microtime(true) <= $end;  $count++){
                $fn();
            }
        }

        $finish = microtime(true);

        return ($count > 0) ? number_format($count) : number_format(1/($finish-$start), 3);
    }
}



class os{
    static function clipboard(string $str){
        if(self::is_windows()){
            $clip = popen('clip', 'w');
            fputs($clip, $str);
            pclose($clip);
        }
    }


    static function is_windows() :bool{
        return preg_match('/^WIN/', PHP_OS);
    }
}


class db{
    public  $pdo;
    private $table;
    private $table_class;


    function __construct(string $file, string $table = ''){
        $this->pdo = new \PDO("sqlite:$file", null, null, [
            PDO::ATTR_ERRMODE=> PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE=> PDO::FETCH_OBJ,
        ]);
        $this->table($table);
    }


    function table($table){
        if(strpos($table, '\\') === 0){
            $this->table = basename($table);
            $this->table_class = $table;
        }
        else{
            $this->table = $table;
            $this->table_class = "";
        }
        return $this;
    }


    function __invoke($table){
        return $this->table($table);
    }


    function table_create(array $data){
        foreach($data as $k => $v){
            $sql_create[] = sprintf('"%s" %s', $k, $v);
        }
        $sql = sprintf('create table if not exists "%s" (%s)', $this->table, implode($sql_create, ','));
        $this->query($sql);
    }


    function table_keys(){
        $sql = sprintf('pragma table_info ("%s")', $this->table);
        return array_column($this->query($sql)->fetchAll(), 'name');
    }


    function insert(array $data){
        foreach(array_keys($data) as $v){
            $sql_keys[]   = sprintf('"%s"', $v);
            $sql_holder[] = '?';
        }

        $sql = sprintf('insert into "%s" (%s) values (%s)', $this->table, implode($sql_keys, ','), implode($sql_holder, ','));
        $this->query($sql, array_values($data));

        return $this->pdo->lastInsertId();
    }


    function update(int $id, array $data){
        foreach($data as $k => $v){
            $sql_set[] = sprintf('"%s" = ?', $k);
        }
        $sql = sprintf('update "%s" set %s where id = %s', $this->table, implode($sql_set, ','), $id);
        $this->query($sql, array_values($data));
    }


    function delete(int $id){
        $sql = sprintf('delete from "%s" where id = %s', $this->table, $id);
        $this->query($sql);
    }


    function select(int $start, $length = 0, bool $reverse = false){
        if(is_string($length)){
            $sql = sprintf('select "%s" from "%s" where id = %s', $length, $this->table, $start);
            return $this->query($sql)->fetchColumn();
        }
        else if($length <= 1){
            $sql = sprintf('select * from "%s" where id = %s', $this->table, $start);
            return $this->query($sql)->fetch();
        }
        else{
            $order = ($reverse) ? 'asc' : 'desc';
            $sql = sprintf('select * from "%s" order by id %s limit %s offset %s', $this->table, $order, $length, $start);
            return $this->query($sql)->fetchAll();
        }
    }


    function search(string $word, $key, int $start, int $length){
        $words = preg_split('/[[:space:]　]+/u', $word);
        $words = array_filter($words, 'strlen');

        foreach((array)$key as $v){
            $keys[] = sprintf('"%s"', $v);
        }

        foreach($words as $v){
            $bind[]     = sprintf('%%%s%%', addcslashes($v, '\\_%'));
            $sql_like[] = sprintf('((%s) like ?)', implode($keys, '||'));
        }

        $sql = sprintf('select * from "%s" where %s order by id desc limit %s offset %s', $this->table, implode($sql_like, ' or '), $length, $start);
        return $this->query($sql, $bind)->fetchAll();
    }


    function query(string $sql, array $bind = []){
        if($bind){
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute($bind);
        }
        else{
            $stmt = $this->pdo->query($sql);
        }

        if($this->table_class){
            $stmt->setFetchMode(PDO::FETCH_CLASS, $this->table_class);
        }
        return $stmt;
    }


    function count(){
        $sql = sprintf('select count (*) from "%s"', $this->table);
        return $this->query($sql)->fetchColumn();
    }


    function transaction(callable $fn, ...$args){
        try{
            $this->pdo->beginTransaction();
            $result = $fn($this, ...$args);
            $this->pdo->commit();
            return $result;
        }
        catch(Exception $e){
            $this->pdo->rollBack();
            throw $e;
        }
    }
}



class doc{
    public $doc;
    public static $dir;

    function __construct($html = '<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><title></title></head><body></body></html>'){
        $html = trim($html);
        $this->doc = new \DOMDocument(); // https://www.php.net/manual/ja/class.domdocument.php

        libxml_use_internal_errors(true);

        if($html[1] === '?'){
            $this->doc->type = 'xml';
            $this->doc->loadXML($html, LIBXML_NONET | LIBXML_COMPACT | LIBXML_PARSEHUGE); // https://www.php.net/manual/ja/libxml.constants.php
        }
        else if($html[1] === '!'){
            $this->doc->type = 'html';
            $this->doc->loadHTML($html, LIBXML_HTML_NODEFDTD | LIBXML_HTML_NOIMPLIED | LIBXML_NONET | LIBXML_COMPACT | LIBXML_PARSEHUGE);
            $this->html  = $this->doc->getElementsByTagName('html')[0];
            $this->head  = $this->doc->getElementsByTagName('head')[0];
            $this->body  = $this->doc->getElementsByTagName('body')[0];
            $this->title = $this->doc->getElementsByTagName('title')[0];
        }
        else{
            $this->doc->type = 'fragment';
            $html = '<?xml encoding="utf-8">' . $html;
            $this->doc->loadHTML($html, LIBXML_HTML_NODEFDTD | LIBXML_HTML_NOIMPLIED | LIBXML_NONET | LIBXML_COMPACT | LIBXML_PARSEHUGE);
        }

        $this->set_id();
    }


    function __invoke($selector, $text = '', $attr = []){
        if($selector instanceof self){
            return $this->doc->importNode($selector->doc->documentElement, true);
        }
        else if($selector instanceof \DOMElement){
            return $this->doc->importNode($selector, true);
        }
        else if($selector[0] === '<'){
            $tagName = str_replace(['<','>'], '', $selector);
            $el = $this->doc->createElement($tagName);
            foreach($attr as $k => $v){
                $el->setAttribute($k, $v);
            }

            if(is_array($text)){
                if($tagName === 'table'){
                    $el = $this->createTableElement($el, $text);
                }
                else if($tagName === 'select'){
                    $el = $this->createSelectElement($el, $text);
                }
                else if($tagName === 'ol' or $tagName === 'ul'){
                    $el = $this->createListElement($el, $text);
                }
            }
            else{
                $el->textContent = $text;
            }

            return $el;
        }
        else if($selector[0] === '.'){
            $query = sprintf('//*[contains(@class, "%s")]', substr($selector, 1));
            return (new \DOMXPath($this->doc))->query($query);
        }
        else if($selector[0] === '['){
            $query = sprintf('//*[@%s', substr($selector, 1));
            return (new \DOMXPath($this->doc))->query($query);
        }
        else if($selector[0] === '#'){
            return $this->doc->getElementById(substr($selector, 1));
        }
        else if($selector === '*'){
            return (new \DOMXPath($this->doc))->query('//*');
        }
        else{
            return $this->doc->getElementsByTagName($selector);
        }
    }


    function __toString(){
        $this->doc->formatOutput = true;

        if(self::$dir){
            $this->replace_doctag($this);
        }

        if($this->doc->type === 'html'){
            return $this->doc->saveXML($this->doc->doctype) . "\n" . $this->doc->saveHTML($this->doc->documentElement);
        }
        else if($this->doc->type === 'xml'){
            return $this->doc->saveXML($this->doc->documentElement);
        }
        else{
            return $this->doc->saveHTML($this->doc->documentElement);
        }
    }


    private function set_id(){
        foreach((new \DOMXPath($this->doc))->query('//*[@id]') as $v){
            $id = $v->getAttribute('id');
            $this->$id = $v;
            if(preg_match('/-/', $id)){
                $id = str_replace('-', '_', $id);
                $this->$id = $v;
            }
        }
    }


    private function createListElement($el, array $contents){
        foreach($contents as $v){
            $child = $this->doc->createElement('li', $v);
            $el->appendChild($child);
        }
        return $el;
    }


    private function createSelectElement($el, array $contents){
        foreach($contents as $v){
            $child = $this->doc->createElement('option', $v);
            $child->setAttribute('value', $v);
            $el->appendChild($child);
        }
        return $el;
    }


    private function createTableElement($el, array $contents){
        foreach($contents as $row){
            $tr = $this->doc->createElement('tr');
            $el->appendChild($tr);
            foreach((array)$row as $cell){
                $td = $this->doc->createElement('td', $cell);
                $tr->appendChild($td);
            }
        }
        return $el;
    }


    private function replace_doctag($DOC){
        foreach($this('*') as $doctag){
            if(strpos($doctag->tagName, 'doc-') === 0){
                $DOC->tag = $doctag;
                $docfile  = sprintf('%s/%s.php', self::$dir, $doctag->tagName);
                $doc      = $this->require_docfile($docfile, $DOC);
                ($doc) ? $doctag->parentNode->replaceChild($doc, $doctag) : $doctag->parentNode->removeChild($doctag);
            }
        }
    }


    private function require_docfile($docfile, $DOC){
        $doc = require($docfile);
        if($doc instanceof self){
            $doc->replace_doctag($DOC);
            return $this->doc->importNode($doc->doc->documentElement, true);
        }
    }
}




class iarray implements \ArrayAccess, \IteratorAggregate, \Countable{
    private $array;


    function __construct(array $array = []){
        $this->array = $array;
    }


    function offsetSet($name, $value){
        $array = &$this->array;
        $keys  = explode('.', $name);

        if(in_array('', $keys)){
            throw new \Exception('キー名が不正です');
        }

        while(count($keys) > 1){
            $k = array_shift($keys);

            if(!isset($array[$k])){
                $array[$k] = [];
            }
            elseif(!is_array($array[$k])){
                throw new \Exception('代入できない場所です');
            }

            $array = &$array[$k];
        }

        if(!isset($array[$keys[0]])){
            $array[$keys[0]] = $value;
        }
        else{
            throw new \Exception('再代入はできません');
        }
    }


    function offsetGet($name){
        $array = $this->array;

        foreach(explode('.', $name) as $k){
            if(isset($array[$k])){
                $array = $array[$k];
            }
            else{
                throw new \Exception('存在しないキーです');
            }
        }
        return $array;
    }


    function offsetExists($name){
        $array = $this->array;

        foreach(explode('.', $name) as $k){
            if(isset($array[$k])){
                $array = $array[$k];
            }
            else{
                return false;
            }
        }
        return true;
    }


    function offsetUnset($offset){
        throw new \Exception('キーは削除できません');
    }


    function getIterator(){
        return new \ArrayIterator($this->array);
    }


    function count() { 
        return count($this->array);
    }


    function __invoke(){
        return $this->array;
    }
}



class ftp{
    private $ftp;

    function __construct(string $host, string $id, string $password, bool $is_ssl = true){
        $this->ftp = ($is_ssl) ? ftp_ssl_connect($host) : ftp_connect($host);
        ftp_login($this->ftp, $id, $password);
        ftp_pasv($this->ftp, true);
    }


    function __destruct(){
        @ftp_close($this->ftp); // ftp_close() SSL_read on shutdown エラー抑制
    }


    function upload(string $from, string $to){
        ftp_put($this->ftp, $to, $from, FTP_BINARY);
    }


    function delete_file(string $to) :bool{
        return ftp_delete($this->ftp, $to);
    }


    function mirroring_upload(string $from, string $to) :array{
        $server = [];
        foreach(ftp_mlsd($this->ftp, $to) as $v){
            if($v['type'] === 'file'){
                $server[$v['name']] = $v['modify'];
            }
        }

        $result = [];
        foreach(file::list($from, false) as $v){
            $name = str::pop($v, '/'); // basename($v) はバグるから使わない
            if(!isset($server[$name]) or date('YmdHis', filemtime($v)) > $server[$name]){
                $this->upload($v, "$to/$name"); // サーバーにない場合と、ローカルの方が新しい場合はアップ
                $result[] = $v;
            }
        }
        return $result;
    }
}



class mail{
    private $to     = '';
    private $from   = '';
    private $title  = '';
    private $body   = '';
    private $name   = '';
    private $file   = [];
    private $header = ['MIME-Version: 1.0', 'Content-Transfer-Encoding: base64'];


    function __construct(string $to, string $from, string $title, string $body){
        $this->to    = str_replace(["\r","\n"," ",","], '', $to);
        $this->from  = str_replace(["\r","\n"," ",","], '', $from);
        $this->title = str_replace(["\r","\n"] , '', $title);
        $this->body  = $body;
    }


    function from(string $name){
        $this->name = str_replace(["\r","\n",","], '', $name);
        return $this;
    }


    function file(string $value, string $name){
        $this->file[$name] = $value;
        return $this;
    }


    function cc(string $cc){
        $cc = str_replace(["\r","\n"," ",","], '', $cc);
        $this->header[] = "Cc: $cc";
        return $this;
    }


    function bcc(string $bcc){
        $bcc = str_replace(["\r","\n"," ",","], '', $bcc);
        $this->header[] = "Bcc: $bcc";
        return $this;
    }


    function header(string $header){
        $this->header[] = str_replace(["\r","\n"], '', $header);
        return $this;
    }


    function send(){
        $title  = mb_encode_mimeheader($this->title, 'utf-8');
        $body   = ($this->file) ? $this->build_multipart() : $this->build_body();
        $header = $this->build_header();
        return mail($this->to, $title, $body, $header);
    }


    private function build_body(){
        $this->header[] = 'Content-Type: text/plain; charset=utf-8';
        return chunk_split(base64_encode($this->body));
    }


    private function build_multipart(){
        $_ = sprintf('__%s__', uniqid());
        $n = "\r\n";

        $this->header[] = sprintf('Content-Type: multipart/mixed; boundary="%s"', $_);

        $body  = sprintf('--%s%s', $_, $n);
        $body .= sprintf('Content-Transfer-Encoding: base64%s', $n);
        $body .= sprintf('Content-Type: text/plain; charset="utf-8"%s%s', $n, $n);
        $body .= chunk_split(base64_encode($this->body)) . $n;

        foreach($this->file as $k => $v){
            $v = is_resource($v) ? stream_get_contents($v) : file_get_contents($v);
            if($v === false){
                continue;
            }
            $body .= sprintf('--%s%s', $_, $n);
            $body .= sprintf('Content-Type: %s%s', file::mime($k), $n);
            $body .= sprintf('Content-Transfer-Encoding: base64%s', $n);
            $body .= sprintf('Content-Disposition: attachment; filename="%s"%s%s', mb_encode_mimeheader($k,'utf-8'), $n, $n);
            $body .= chunk_split(base64_encode($v)) . $n;
        }

        $body .= sprintf('--%s--%s', $_, $n);
        return $body;
    }


    private function build_header(){
        if(strlen($this->name)){
            $this->header[] = sprintf('From: %s <%s>', mb_encode_mimeheader($this->name,'utf-8'), $this->from);
        }
        else{
            $this->header[] = "From: $this->from";
        }

        return implode("\r\n", $this->header) . "\r\n";
    }
}



trait immutable{
    private $property = [];

    function __get($name){
        return $this->property[$name];
    }

    function __set($name, $value){
        if(isset($this->property[$name])){
            throw new Exception("Property '$name' is immutable.");
        }
        else{
            $this->property[$name] = $value;
        }
    }

    function __isset($name){
        return isset($this->property[$name]);
    }

    function __unset($name){
       throw new Exception("Property '$name' is immutable.");
    }
}
