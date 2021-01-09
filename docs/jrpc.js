// APIのURLを設定する。API側ではjrpc()を実行する
const url = 'http://127.0.0.1/index.php'


function get(target, name){
    return call_method.bind(name)
}


async function call_method(...args){
    const base64 = []

    for(const [i, v] of args.entries()){
        if(is_file(v)){
            args[i] = await read_file(v)
            base64.push(i)
        }
    }

    const response = await fetch(url, {
        method: 'POST',
        body: JSON.stringify({method:this, args, base64}),
        mode: 'cors',
    })

    const json = await response.json()

    if(json.error){
        throw json.error
    }

    return json.result
}


function is_file(v){
    const type = Object.prototype.toString.call(v).slice(8, -1)
    return (type === 'File' || type === 'Blob')
}


function read_file(file){
    function async(ok, ng){
        const reader = new FileReader()
        reader.onload = () => ok(reader.result.replace(/^.+?,/, ''))
        reader.readAsDataURL(file)
    }
    return new Promise(async)
}


export default new Proxy({}, {get})
