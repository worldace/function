<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <title>CSSセレクタ発見器</title>
  <style>
body{
    font-family:"Meiryo", sans-serif;
}
div{
    margin-bottom: 20px;
}
h1{
    border-top: solid 1px #000;
    font-size: 16px;
    padding-top:6px;
    margin-bottom: 0;
}
span{
    font-size: 12px;
    color: #444;
}
</style>
</head>
<body>

<form action="selector.php" method="POST">
<input type="text" name="url" value="" style="width:600px;"><input type="submit" value="URL解析">
</form>

<?php
if(!preg_match("|^https?://|", @$_POST['url'])){
    exit;
}

ini_set('user_agent', 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36');
libxml_use_internal_errors(true);
libxml_disable_entity_loader(true);


$文書 = new DOMDocument();
$文書->loadHTML("<?xml encoding='UTF-8'>".file_get_contents($_POST['url']), LIBXML_COMPACT);

$url = htmlspecialchars($_POST['url'], ENT_QUOTES, "UTF-8");
print "<p>{$url} の解析結果</p>";

foreach((new DOMXPath($文書))->query("//*") as $v){
    $xpath = $v->getNodePath();
    $xpath = str_replace("/", ">", $xpath);
    $xpath = preg_replace("#^>#", "", $xpath);
    $xpath = preg_replace("#\[(\d+)\]#", ":nth-of-type($1)", $xpath);
    $xpath = htmlspecialchars($xpath, ENT_QUOTES, "UTF-8");
    $html  = htmlspecialchars($文書->saveHTML($v), ENT_QUOTES, "UTF-8");
    $html  = nl2br($html);
    print "<div><h1>[$key:セレクタ] '$xpath'</h1><span>$html</span></div>";
}

