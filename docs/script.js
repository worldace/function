/*! highlight.js v9.15.9 https://highlightjs.org/ */
!function(e){var n="object"==typeof window&&window||"object"==typeof self&&self;"undefined"==typeof exports||exports.nodeType?n&&(n.hljs=e({}),"function"==typeof define&&define.amd&&define([],function(){return n.hljs})):e(exports)}(function(a){var f=[],u=Object.keys,N={},c={},n=/^(no-?highlight|plain|text)$/i,s=/\blang(?:uage)?-([\w-]+)\b/i,t=/((^(<[^>]+>|\t|)+|(?:\n)))/gm,r={case_insensitive:"cI",lexemes:"l",contains:"c",keywords:"k",subLanguage:"sL",className:"cN",begin:"b",beginKeywords:"bK",end:"e",endsWithParent:"eW",illegal:"i",excludeBegin:"eB",excludeEnd:"eE",returnBegin:"rB",returnEnd:"rE",relevance:"r",variants:"v",IDENT_RE:"IR",UNDERSCORE_IDENT_RE:"UIR",NUMBER_RE:"NR",C_NUMBER_RE:"CNR",BINARY_NUMBER_RE:"BNR",RE_STARTERS_RE:"RSR",BACKSLASH_ESCAPE:"BE",APOS_STRING_MODE:"ASM",QUOTE_STRING_MODE:"QSM",PHRASAL_WORDS_MODE:"PWM",C_LINE_COMMENT_MODE:"CLCM",C_BLOCK_COMMENT_MODE:"CBCM",HASH_COMMENT_MODE:"HCM",NUMBER_MODE:"NM",C_NUMBER_MODE:"CNM",BINARY_NUMBER_MODE:"BNM",CSS_NUMBER_MODE:"CSSNM",REGEXP_MODE:"RM",TITLE_MODE:"TM",UNDERSCORE_TITLE_MODE:"UTM",COMMENT:"C",beginRe:"bR",endRe:"eR",illegalRe:"iR",lexemesRe:"lR",terminators:"t",terminator_end:"tE"},b="</span>",h={classPrefix:"hljs-",tabReplace:null,useBR:!1,languages:void 0};function _(e){return e.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")}function E(e){return e.nodeName.toLowerCase()}function v(e,n){var t=e&&e.exec(n);return t&&0===t.index}function l(e){return n.test(e)}function g(e){var n,t={},r=Array.prototype.slice.call(arguments,1);for(n in e)t[n]=e[n];return r.forEach(function(e){for(n in e)t[n]=e[n]}),t}function R(e){var a=[];return function e(n,t){for(var r=n.firstChild;r;r=r.nextSibling)3===r.nodeType?t+=r.nodeValue.length:1===r.nodeType&&(a.push({event:"start",offset:t,node:r}),t=e(r,t),E(r).match(/br|hr|img|input/)||a.push({event:"stop",offset:t,node:r}));return t}(e,0),a}function i(e){if(r&&!e.langApiRestored){for(var n in e.langApiRestored=!0,r)e[n]&&(e[r[n]]=e[n]);(e.c||[]).concat(e.v||[]).forEach(i)}}function m(o){function s(e){return e&&e.source||e}function c(e,n){return new RegExp(s(e),"m"+(o.cI?"i":"")+(n?"g":""))}!function n(t,e){if(!t.compiled){if(t.compiled=!0,t.k=t.k||t.bK,t.k){function r(t,e){o.cI&&(e=e.toLowerCase()),e.split(" ").forEach(function(e){var n=e.split("|");a[n[0]]=[t,n[1]?Number(n[1]):1]})}var a={};"string"==typeof t.k?r("keyword",t.k):u(t.k).forEach(function(e){r(e,t.k[e])}),t.k=a}t.lR=c(t.l||/\w+/,!0),e&&(t.bK&&(t.b="\\b("+t.bK.split(" ").join("|")+")\\b"),t.b||(t.b=/\B|\b/),t.bR=c(t.b),t.endSameAsBegin&&(t.e=t.b),t.e||t.eW||(t.e=/\B|\b/),t.e&&(t.eR=c(t.e)),t.tE=s(t.e)||"",t.eW&&e.tE&&(t.tE+=(t.e?"|":"")+e.tE)),t.i&&(t.iR=c(t.i)),null==t.r&&(t.r=1),t.c||(t.c=[]),t.c=Array.prototype.concat.apply([],t.c.map(function(e){return function(n){return n.v&&!n.cached_variants&&(n.cached_variants=n.v.map(function(e){return g(n,{v:null},e)})),n.cached_variants||n.eW&&[g(n)]||[n]}("self"===e?t:e)})),t.c.forEach(function(e){n(e,t)}),t.starts&&n(t.starts,e);var i=t.c.map(function(e){return e.bK?"\\.?(?:"+e.b+")\\.?":e.b}).concat([t.tE,t.i]).map(s).filter(Boolean);t.t=i.length?c(function(e,n){for(var t=/\[(?:[^\\\]]|\\.)*\]|\(\??|\\([1-9][0-9]*)|\\./,r=0,a="",i=0;i<e.length;i++){var o=r,c=s(e[i]);for(0<i&&(a+=n);0<c.length;){var u=t.exec(c);if(null==u){a+=c;break}a+=c.substring(0,u.index),c=c.substring(u.index+u[0].length),"\\"==u[0][0]&&u[1]?a+="\\"+String(Number(u[1])+o):(a+=u[0],"("==u[0]&&r++)}}return a}(i,"|"),!0):{exec:function(){return null}}}}(o)}function C(e,n,i,t){function c(e,n,t,r){var a='<span class="'+(r?"":h.classPrefix);return e?(a+=e+'">')+n+(t?"":b):n}function o(){E+=null!=l.sL?function(){var e="string"==typeof l.sL;if(e&&!N[l.sL])return _(g);var n=e?C(l.sL,g,!0,f[l.sL]):O(g,l.sL.length?l.sL:void 0);return 0<l.r&&(R+=n.r),e&&(f[l.sL]=n.top),c(n.language,n.value,!1,!0)}():function(){var e,n,t,r,a,i,o;if(!l.k)return _(g);for(r="",n=0,l.lR.lastIndex=0,t=l.lR.exec(g);t;)r+=_(g.substring(n,t.index)),a=l,i=t,void 0,o=s.cI?i[0].toLowerCase():i[0],(e=a.k.hasOwnProperty(o)&&a.k[o])?(R+=e[1],r+=c(e[0],_(t[0]))):r+=_(t[0]),n=l.lR.lastIndex,t=l.lR.exec(g);return r+_(g.substr(n))}(),g=""}function u(e){E+=e.cN?c(e.cN,"",!0):"",l=Object.create(e,{parent:{value:l}})}function r(e,n){if(g+=e,null==n)return o(),0;var t=function(e,n){var t,r,a;for(t=0,r=n.c.length;t<r;t++)if(v(n.c[t].bR,e))return n.c[t].endSameAsBegin&&(n.c[t].eR=(a=n.c[t].bR.exec(e)[0],new RegExp(a.replace(/[-\/\\^$*+?.()|[\]{}]/g,"\\$&"),"m"))),n.c[t]}(n,l);if(t)return t.skip?g+=n:(t.eB&&(g+=n),o(),t.rB||t.eB||(g=n)),u(t),t.rB?0:n.length;var r=function e(n,t){if(v(n.eR,t)){for(;n.endsParent&&n.parent;)n=n.parent;return n}if(n.eW)return e(n.parent,t)}(l,n);if(r){var a=l;for(a.skip?g+=n:(a.rE||a.eE||(g+=n),o(),a.eE&&(g=n));l.cN&&(E+=b),l.skip||l.sL||(R+=l.r),(l=l.parent)!==r.parent;);return r.starts&&(r.endSameAsBegin&&(r.starts.eR=r.eR),u(r.starts)),a.rE?0:n.length}if(function(e,n){return!i&&v(n.iR,e)}(n,l))throw new Error('Illegal lexeme "'+n+'" for mode "'+(l.cN||"<unnamed>")+'"');return g+=n,n.length||1}var s=B(e);if(!s)throw new Error('Unknown language: "'+e+'"');m(s);var a,l=t||s,f={},E="";for(a=l;a!==s;a=a.parent)a.cN&&(E=c(a.cN,"",!0)+E);var g="",R=0;try{for(var d,p,M=0;l.t.lastIndex=M,d=l.t.exec(n);)p=r(n.substring(M,d.index),d[0]),M=d.index+p;for(r(n.substr(M)),a=l;a.parent;a=a.parent)a.cN&&(E+=b);return{r:R,value:E,language:e,top:l}}catch(e){if(e.message&&-1!==e.message.indexOf("Illegal"))return{r:0,value:_(n)};throw e}}function O(t,e){e=e||h.languages||u(N);var r={r:0,value:_(t)},a=r;return e.filter(B).filter(M).forEach(function(e){var n=C(e,t,!1);n.language=e,n.r>a.r&&(a=n),n.r>r.r&&(a=r,r=n)}),a.language&&(r.second_best=a),r}function d(e){return h.tabReplace||h.useBR?e.replace(t,function(e,n){return h.useBR&&"\n"===e?"<br>":h.tabReplace?n.replace(/\t/g,h.tabReplace):""}):e}function o(e){var n,t,r,a,i,o=function(e){var n,t,r,a,i=e.className+" ";if(i+=e.parentNode?e.parentNode.className:"",t=s.exec(i))return B(t[1])?t[1]:"no-highlight";for(n=0,r=(i=i.split(/\s+/)).length;n<r;n++)if(l(a=i[n])||B(a))return a}(e);l(o)||(h.useBR?(n=document.createElementNS("http://www.w3.org/1999/xhtml","div")).innerHTML=e.innerHTML.replace(/\n/g,"").replace(/<br[ \/]*>/g,"\n"):n=e,i=n.textContent,r=o?C(o,i,!0):O(i),(t=R(n)).length&&((a=document.createElementNS("http://www.w3.org/1999/xhtml","div")).innerHTML=r.value,r.value=function(e,n,t){var r=0,a="",i=[];function o(){return e.length&&n.length?e[0].offset!==n[0].offset?e[0].offset<n[0].offset?e:n:"start"===n[0].event?e:n:e.length?e:n}function c(e){a+="<"+E(e)+f.map.call(e.attributes,function(e){return" "+e.nodeName+'="'+_(e.value).replace('"',"&quot;")+'"'}).join("")+">"}function u(e){a+="</"+E(e)+">"}function s(e){("start"===e.event?c:u)(e.node)}for(;e.length||n.length;){var l=o();if(a+=_(t.substring(r,l[0].offset)),r=l[0].offset,l===e){for(i.reverse().forEach(u);s(l.splice(0,1)[0]),(l=o())===e&&l.length&&l[0].offset===r;);i.reverse().forEach(c)}else"start"===l[0].event?i.push(l[0].node):i.pop(),s(l.splice(0,1)[0])}return a+_(t.substr(r))}(t,R(a),i)),r.value=d(r.value),e.innerHTML=r.value,e.className=function(e,n,t){var r=n?c[n]:t,a=[e.trim()];return e.match(/\bhljs\b/)||a.push("hljs"),-1===e.indexOf(r)&&a.push(r),a.join(" ").trim()}(e.className,o,r.language),e.result={language:r.language,re:r.r},r.second_best&&(e.second_best={language:r.second_best.language,re:r.second_best.r}))}function p(){if(!p.called){p.called=!0;var e=document.querySelectorAll("pre code");f.forEach.call(e,o)}}function B(e){return e=(e||"").toLowerCase(),N[e]||N[c[e]]}function M(e){var n=B(e);return n&&!n.disableAutodetect}return a.highlight=C,a.highlightAuto=O,a.fixMarkup=d,a.highlightBlock=o,a.configure=function(e){h=g(h,e)},a.initHighlighting=p,a.initHighlightingOnLoad=function(){addEventListener("DOMContentLoaded",p,!1),addEventListener("load",p,!1)},a.registerLanguage=function(n,e){var t=N[n]=e(a);i(t),t.aliases&&t.aliases.forEach(function(e){c[e]=n})},a.listLanguages=function(){return u(N)},a.getLanguage=B,a.autoDetection=M,a.inherit=g,a.IR=a.IDENT_RE="[a-zA-Z]\\w*",a.UIR=a.UNDERSCORE_IDENT_RE="[a-zA-Z_]\\w*",a.NR=a.NUMBER_RE="\\b\\d+(\\.\\d+)?",a.CNR=a.C_NUMBER_RE="(-?)(\\b0[xX][a-fA-F0-9]+|(\\b\\d+(\\.\\d*)?|\\.\\d+)([eE][-+]?\\d+)?)",a.BNR=a.BINARY_NUMBER_RE="\\b(0b[01]+)",a.RSR=a.RE_STARTERS_RE="!|!=|!==|%|%=|&|&&|&=|\\*|\\*=|\\+|\\+=|,|-|-=|/=|/|:|;|<<|<<=|<=|<|===|==|=|>>>=|>>=|>=|>>>|>>|>|\\?|\\[|\\{|\\(|\\^|\\^=|\\||\\|=|\\|\\||~",a.BE=a.BACKSLASH_ESCAPE={b:"\\\\[\\s\\S]",r:0},a.ASM=a.APOS_STRING_MODE={cN:"string",b:"'",e:"'",i:"\\n",c:[a.BE]},a.QSM=a.QUOTE_STRING_MODE={cN:"string",b:'"',e:'"',i:"\\n",c:[a.BE]},a.PWM=a.PHRASAL_WORDS_MODE={b:/\b(a|an|the|are|I'm|isn't|don't|doesn't|won't|but|just|should|pretty|simply|enough|gonna|going|wtf|so|such|will|you|your|they|like|more)\b/},a.C=a.COMMENT=function(e,n,t){var r=a.inherit({cN:"comment",b:e,e:n,c:[]},t||{});return r.c.push(a.PWM),r.c.push({cN:"doctag",b:"(?:TODO|FIXME|NOTE|BUG|XXX):",r:0}),r},a.CLCM=a.C_LINE_COMMENT_MODE=a.C("//","$"),a.CBCM=a.C_BLOCK_COMMENT_MODE=a.C("/\\*","\\*/"),a.HCM=a.HASH_COMMENT_MODE=a.C("#","$"),a.NM=a.NUMBER_MODE={cN:"number",b:a.NR,r:0},a.CNM=a.C_NUMBER_MODE={cN:"number",b:a.CNR,r:0},a.BNM=a.BINARY_NUMBER_MODE={cN:"number",b:a.BNR,r:0},a.CSSNM=a.CSS_NUMBER_MODE={cN:"number",b:a.NR+"(%|em|ex|ch|rem|vw|vh|vmin|vmax|cm|mm|in|pt|pc|px|deg|grad|rad|turn|s|ms|Hz|kHz|dpi|dpcm|dppx)?",r:0},a.RM=a.REGEXP_MODE={cN:"regexp",b:/\//,e:/\/[gimuy]*/,i:/\n/,c:[a.BE,{b:/\[/,e:/\]/,r:0,c:[a.BE]}]},a.TM=a.TITLE_MODE={cN:"title",b:a.IR,r:0},a.UTM=a.UNDERSCORE_TITLE_MODE={cN:"title",b:a.UIR,r:0},a.METHOD_GUARD={b:"\\.\\s*"+a.UIR,r:0},a});hljs.registerLanguage("json",function(e){var i={literal:"true false null"},n=[e.QSM,e.CNM],r={e:",",eW:!0,eE:!0,c:n,k:i},t={b:"{",e:"}",c:[{cN:"attr",b:/"/,e:/"/,c:[e.BE],i:"\\n"},e.inherit(r,{b:/:/})],i:"\\S"},c={b:"\\[",e:"\\]",c:[e.inherit(r)],i:"\\S"};return n.splice(n.length,0,t,c),{c:n,k:i,i:"\\S"}});hljs.registerLanguage("javascript",function(e){var r="[A-Za-z$_][0-9A-Za-z$_]*",a={keyword:"in of if for while finally var new function do return void else break catch instanceof with throw case default try this switch continue typeof delete let yield const export super debugger as async await static import from as",literal:"true false null undefined NaN Infinity",built_in:"eval isFinite isNaN parseFloat parseInt decodeURI decodeURIComponent encodeURI encodeURIComponent escape unescape Object Function Boolean Error EvalError InternalError RangeError ReferenceError StopIteration SyntaxError TypeError URIError Number Math Date String RegExp Array Float32Array Float64Array Int16Array Int32Array Int8Array Uint16Array Uint32Array Uint8Array Uint8ClampedArray ArrayBuffer DataView JSON Intl arguments require module console window document Symbol Set Map WeakSet WeakMap Proxy Reflect Promise"},t={cN:"number",v:[{b:"\\b(0[bB][01]+)"},{b:"\\b(0[oO][0-7]+)"},{b:e.CNR}],r:0},n={cN:"subst",b:"\\$\\{",e:"\\}",k:a,c:[]},c={cN:"string",b:"`",e:"`",c:[e.BE,n]};n.c=[e.ASM,e.QSM,c,t,e.RM];var s=n.c.concat([e.CBCM,e.CLCM]);return{aliases:["js","jsx"],k:a,c:[{cN:"meta",r:10,b:/^\s*['"]use (strict|asm)['"]/},{cN:"meta",b:/^#!/,e:/$/},e.ASM,e.QSM,c,e.CLCM,e.CBCM,t,{b:/[{,]\s*/,r:0,c:[{b:r+"\\s*:",rB:!0,r:0,c:[{cN:"attr",b:r,r:0}]}]},{b:"("+e.RSR+"|\\b(case|return|throw)\\b)\\s*",k:"return throw case",c:[e.CLCM,e.CBCM,e.RM,{cN:"function",b:"(\\(.*?\\)|"+r+")\\s*=>",rB:!0,e:"\\s*=>",c:[{cN:"params",v:[{b:r},{b:/\(\s*\)/},{b:/\(/,e:/\)/,eB:!0,eE:!0,k:a,c:s}]}]},{cN:"",b:/\s/,e:/\s*/,skip:!0},{b:/</,e:/(\/[A-Za-z0-9\\._:-]+|[A-Za-z0-9\\._:-]+\/)>/,sL:"xml",c:[{b:/<[A-Za-z0-9\\._:-]+\s*\/>/,skip:!0},{b:/<[A-Za-z0-9\\._:-]+/,e:/(\/[A-Za-z0-9\\._:-]+|[A-Za-z0-9\\._:-]+\/)>/,skip:!0,c:[{b:/<[A-Za-z0-9\\._:-]+\s*\/>/,skip:!0},"self"]}]}],r:0},{cN:"function",bK:"function",e:/\{/,eE:!0,c:[e.inherit(e.TM,{b:r}),{cN:"params",b:/\(/,e:/\)/,eB:!0,eE:!0,c:s}],i:/\[|%/},{b:/\$[(.]/},e.METHOD_GUARD,{cN:"class",bK:"class",e:/[{;=]/,eE:!0,i:/[:"\[\]]/,c:[{bK:"extends"},e.UTM]},{bK:"constructor get set",e:/\{/,eE:!0}],i:/#(?!!)/}});hljs.registerLanguage("php",function(e){var c={b:"\\$+[a-zA-Z_-ÿ][a-zA-Z0-9_-ÿ]*"},i={cN:"meta",b:/<\?(php)?|\?>/},t={cN:"string",c:[e.BE,i],v:[{b:'b"',e:'"'},{b:"b'",e:"'"},e.inherit(e.ASM,{i:null}),e.inherit(e.QSM,{i:null})]},a={v:[e.BNM,e.CNM]};return{aliases:["php","php3","php4","php5","php6","php7"],cI:!0,k:"and include_once list abstract global private echo interface as static endswitch array null if endwhile or const for endforeach self var while isset public protected exit foreach throw elseif include __FILE__ empty require_once do xor return parent clone use __CLASS__ __LINE__ else break print eval new catch __METHOD__ case exception default die require __FUNCTION__ enddeclare final try switch continue endfor endif declare unset true false trait goto instanceof insteadof __DIR__ __NAMESPACE__ yield finally",c:[e.HCM,e.C("//","$",{c:[i]}),e.C("/\\*","\\*/",{c:[{cN:"doctag",b:"@[A-Za-z]+"}]}),e.C("__halt_compiler.+?;",!1,{eW:!0,k:"__halt_compiler",l:e.UIR}),{cN:"string",b:/<<<['"]?\w+['"]?$/,e:/^\w+;?$/,c:[e.BE,{cN:"subst",v:[{b:/\$\w+/},{b:/\{\$/,e:/\}/}]}]},i,{cN:"keyword",b:/\$this\b/},c,{b:/(::|->)+[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*/},{cN:"function",bK:"function",e:/[;{]/,eE:!0,i:"\\$|\\[|%",c:[e.UTM,{cN:"params",b:"\\(",e:"\\)",c:["self",c,e.CBCM,t,a]}]},{cN:"class",bK:"class interface",e:"{",eE:!0,i:/[:\(\$"]/,c:[{bK:"extends implements"},e.UTM]},{bK:"namespace",e:";",i:/[\.']/,c:[e.UTM]},{bK:"use",e:";",c:[e.UTM]},{b:"=>"},t,a]}});hljs.registerLanguage("xml",function(s){var e={eW:!0,i:/</,r:0,c:[{cN:"attr",b:"[A-Za-z0-9\\._:-]+",r:0},{b:/=\s*/,r:0,c:[{cN:"string",endsParent:!0,v:[{b:/"/,e:/"/},{b:/'/,e:/'/},{b:/[^\s"'=<>`]+/}]}]}]};return{aliases:["html","xhtml","rss","atom","xjb","xsd","xsl","plist"],cI:!0,c:[{cN:"meta",b:"<!DOCTYPE",e:">",r:10,c:[{b:"\\[",e:"\\]"}]},s.C("\x3c!--","--\x3e",{r:10}),{b:"<\\!\\[CDATA\\[",e:"\\]\\]>",r:10},{cN:"meta",b:/<\?xml/,e:/\?>/,r:10},{b:/<\?(php)?/,e:/\?>/,sL:"php",c:[{b:"/\\*",e:"\\*/",skip:!0},{b:'b"',e:'"',skip:!0},{b:"b'",e:"'",skip:!0},s.inherit(s.ASM,{i:null,cN:null,c:null,skip:!0}),s.inherit(s.QSM,{i:null,cN:null,c:null,skip:!0})]},{cN:"tag",b:"<style(?=\\s|>|$)",e:">",k:{name:"style"},c:[e],starts:{e:"</style>",rE:!0,sL:["css","xml"]}},{cN:"tag",b:"<script(?=\\s|>|$)",e:">",k:{name:"script"},c:[e],starts:{e:"<\/script>",rE:!0,sL:["actionscript","javascript","handlebars","xml"]}},{cN:"tag",b:"</?",e:"/?>",c:[{cN:"name",b:/[^\/><\s]+/,r:0},e]}]}});hljs.registerLanguage("css",function(e){var c={b:/[A-Z\_\.\-]+\s*:/,rB:!0,e:";",eW:!0,c:[{cN:"attribute",b:/\S/,e:":",eE:!0,starts:{eW:!0,eE:!0,c:[{b:/[\w-]+\(/,rB:!0,c:[{cN:"built_in",b:/[\w-]+/},{b:/\(/,e:/\)/,c:[e.ASM,e.QSM]}]},e.CSSNM,e.QSM,e.ASM,e.CBCM,{cN:"number",b:"#[0-9A-Fa-f]+"},{cN:"meta",b:"!important"}]}}]};return{cI:!0,i:/[=\/|'\$]/,c:[e.CBCM,{cN:"selector-id",b:/#[A-Za-z0-9_-]+/},{cN:"selector-class",b:/\.[A-Za-z0-9_-]+/},{cN:"selector-attr",b:/\[/,e:/\]/,i:"$"},{cN:"selector-pseudo",b:/:(:)?[a-zA-Z0-9\_\-\+\(\)"'.]+/},{b:"@(font-face|page)",l:"[a-z-]+",k:"font-face page"},{b:"@",e:"[{;]",i:/:/,c:[{cN:"keyword",b:/\w+/},{b:/\s/,eW:!0,eE:!0,r:0,c:[e.ASM,e.QSM,e.CSSNM]}]},{cN:"selector-tag",b:"[a-zA-Z-][a-zA-Z0-9_-]*",r:0},{b:"{",e:"}",i:/\S/,c:[e.CBCM,c]}]}});

function highlight(){
    for(const el of document.querySelectorAll('code')){
        if(el.firstChild.nodeType === Node.COMMENT_NODE){
            const code = el.firstChild.textContent.trim().replace(/＜ーー/g, '<--').replace(/ーー＞/g, "-->")
            el.innerHTML = hljs.highlight(el.className, code).value
        }
    }
}

class MyIndex extends HTMLElement{
    connectedCallback(){
        let li = ''
        for(const el of document.querySelectorAll('h2')){
            el.id = el.textContent
            li += `<li><a href="#${encodeURIComponent(el.textContent)}">${el.textContent}</a></li>`
        }
        this.innerHTML = `<ol>${li}</ol>`
    }
}


highlight()
customElements.define('my-index', MyIndex)
