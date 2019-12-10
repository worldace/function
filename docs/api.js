
// PHP側のURLの設定。js::api()を実行できること
const url = 'http://127.0.0.1/api.php';


const api = new Proxy({}, {
    get(target, name){
        return methodMissing.bind(name);
    }
});


async function methodMissing(...args){
    const method = this;
    const base64 = [];

    for(let i = 0; i < args.length; i++){
        if(isFile(args[i])){
            args[i] = await readFile(args[i]);
            base64.push(i);
        }
    }

    const json = JSON.stringify({method, args, base64});
    const response = await fetch(url, {
        method: 'POST',
        body: new URLSearchParams({json}),
        mode: 'cors',
        credentials: 'include',
    });

    const result = await response.json();
    if(result.error){
        throw result.error;
    }
    return result.result;
}


function isFile(v){
    const type = Object.prototype.toString.call(v).slice(8, -1).toLowerCase();
    return (type === 'file' || type === 'blob');
}


function readFile(file){
    function async(ok, ng){
        const reader = new FileReader();
        reader.onload = () => ok(reader.result.replace(/^.+?,/, ''));
        reader.readAsDataURL(file);
    }
    return new Promise(async);
}


export default api;
