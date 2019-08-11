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



class db{
    public  $pdo;
    private $table;
    private $table_class;


    function __construct(string $file, string $table){
        $this->pdo = new \PDO("sqlite:$file", null, null, [
            \PDO::ATTR_ERRMODE=> \PDO::ERRMODE_EXCEPTION,
            \PDO::ATTR_DEFAULT_FETCH_MODE=> \PDO::FETCH_ASSOC,
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
            $stmt->setFetchMode(\PDO::FETCH_CLASS, $this->table_class);
        }
        return $stmt;
    }


    function count(){
        $sql = sprintf('select count (*) from "%s"', $this->table);
        return $this->query($sql)->fetchColumn();
    }


    function transaction(callable $func, ...$args){
        try{
            $this->pdo->beginTransaction();
            $result = $func($this, ...$args);
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

    function __construct($html = '<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><title></title></head><body></body></html>'){
        $html = trim($html);
        $this->doc = new \DOMDocument(); // https://www.php.net/manual/ja/class.domdocument.php

        libxml_use_internal_errors(true);
        libxml_disable_entity_loader(true);

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

        foreach((new \DOMXPath($this->doc))->query('//*[@id]') as $v){
            $id = $v->getAttribute('id');
            $this->$id = $v;
            if(preg_match('/-/', $id)){
                $id = str_replace('-', '_', $id);
                $this->$id = $v;
            }
        }
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
            $el = $this->doc->createElement($tagName, $text);
            foreach($attr as $k => $v){
                $el->setAttribute($k, $v);
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
        else{
            return $this->doc->getElementsByTagName($selector);
        }
    }


    function __toString(){
        $this->doc->formatOutput = true;

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
}

