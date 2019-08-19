class 部品{
    private static $ディレクトリ;
    private static $開始;
    private static $記憶;
    private static $結果;


    public static function 開始($dir = __DIR__."/部品", $manual = false){
        if(!is_dir($dir)){ throw new プログラムミス("部品ディレクトリが存在しません"); }
        self::$ディレクトリ = $dir;
        self::$結果 = ['css'=>'', 'jsinhead'=>'', 'jsinbody'=>''];
        self::$記憶 = [];
        self::関数登録();
        if(!self::$開始 and !$manual){
            self::$開始 = true;
            ob_start(["部品", "差し込み"]);
        }
    }

    public static function 終了(){
        if(self::$開始){
            self::$開始 = null;
            self::$ディレクトリ = null;
            return self::差し込み(ob_get_clean());
        }
    }

    public static function 作成($部品名, $引数){
        //部品変数を初期化
        $html = $css = $cssfile = $js = $jsfile = $jsinhead = "";

        $部品パス = self::パス($部品名);

        //キャッシュの有無により分岐
        if(!isset(self::$記憶[$部品パス])){
            require $部品パス;
            self::$記憶[$部品パス] = $html;

            //部品変数を処理して結果にまとめる
            self::$結果['css'] .= self::CSS変数処理($css, $cssfile, $引数);
            if($jsinhead){ self::$結果['jsinhead'] .= self::JS変数処理($js, $jsfile, $引数); }
            else         { self::$結果['jsinbody'] .= self::JS変数処理($js, $jsfile, $引数); }
        }
        else{
            $html = self::$記憶[$部品パス];
        }

        return is_callable($html)  ?  call_user_func_array($html, $引数)  :  $html;
    }

    public static function 差し込み($buf){
        if(self::$結果['jsinbody']){
            $pos = strripos($buf, "</body>");
            if($pos !== false){
                $buf = substr_replace($buf, self::$結果['jsinbody'], $pos, 0); //最後に出現する</body>の前にJSを挿入する
            }
        }
        if(self::$結果['css'] || self::$結果['jsinhead']){
            $pos = stripos($buf, "</head>");
            if($pos !== false){
                $buf = substr_replace($buf, self::$結果['css'].self::$結果['jsinhead'], $pos, 0); //最初に出現する</head>の前に挿入する
            }
        }
        return $buf;
    }

    public static function 関数登録(){
        if(function_exists("部品")){ return; }
        function 部品($部品名, ...$引数){
            return 部品::作成($部品名, h($引数));
        }
        function 生部品($部品名, ...$引数){
            return 部品::作成($部品名, $引数);
        }
    }

    public static function コード取得(){
        return $this->結果;
    }


    private static function パス($部品名){
        if(!self::$ディレクトリ){ throw new プログラムミス("部品::開始() を行っていません"); }

        if(preg_match("/\.php$/i", $部品名)){
            $path = (preg_match("#^(/|\\\\|\w+:)#", $部品名))  ?  $部品名  :  dirname(debug_backtrace()[2]['file']) . $部品名; //絶対パスor相対パス
        }
        else{
            $path = self::$ディレクトリ . "/$部品名.php";
        }
        $path = realpath($path);
        if(!$path){ throw new プログラムミス("部品ファイルが見つかりません\n部品名: $部品名\n部品パス: $path"); }

        return $path;
    }

    private static function CSS変数処理($css, $cssfile, $引数){
        if($css){
            $css  = is_callable($css)  ?  call_user_func_array($css, $引数)  :  $css;
            $css  = ltrim($css);
            $_css = preg_match("/^</", $css)  ?  "$css\n"  :  "<style>\n$css\n</style>\n";
        }
        if($cssfile){
            $cssfile = is_callable($cssfile)  ?  call_user_func_array($cssfile, $引数)  :  $cssfile;
            foreach((array)$cssfile as $url){
                if(in_array($url, (array)self::$記憶['読み込み済みURL'])){ continue; }
                self::$記憶['読み込み済みURL'][] = $url;
                $_cssfile .= "<link rel=\"stylesheet\" href=\"$url\">\n";
            }
        }
        return $_cssfile . $_css;
    }

    private static function JS変数処理($js, $jsfile, $引数){
        if($js){
            $js  = is_callable($js)  ?  call_user_func_array($js, $引数)  :  $js;
            $js  = ltrim($js);
            $_js = preg_match("/^</", $js)  ?  "$js\n"  :  "<script>\n$js\n</script>\n";
        }
        if($jsfile){
            $jsfile = is_callable($jsfile)  ?  call_user_func_array($jsfile, $引数)  :  $jsfile;
            foreach((array)$jsfile as $url){
                if(in_array($url, (array)self::$記憶['読み込み済みURL'])){ continue; }
                self::$記憶['読み込み済みURL'][] = $url;
                $_jsfile .= "<script src=\"$url\"></script>\n";
            }
        }
        return $_jsfile . $_js;
    }
}
