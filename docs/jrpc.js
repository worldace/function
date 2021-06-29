// APIのURLを設定する。API側ではjrpc()を実行する
const url = 'http://127.0.0.1/index.php'

const proxy = new Proxy({}, {get:(_,name) => http.bind(name)})


async function http(...args){
    const base64 = []

    for(const [i, v] of args.entries()){
        if(v instanceof Blob){
            args[i] = await toDataURL(v)
            base64.push(i)
        }
    }

    const response = await fetch(url, {method:'POST', body:JSON.stringify({fn:this, args, base64})})

    if(!response.headers.get('Content-Type').includes('json')){
        throw await response.text()
    }

    return await response.json()
}


function toDataURL(file){
    function async(ok, ng){
        const reader = new FileReader()
        reader.onload = event => ok(event.target.result.replace(/^.+?,/, ''))
        reader.readAsDataURL(file)
    }
    return new Promise(async)
}


export default proxy
