
// js::api()を実行できるURL
const url = 'http://127.0.0.1/api.php';


const api = new Proxy({}, {
    get(target, name){
        return methodMissing.bind(name);
    }
});

async function methodMissing(...args){
    const json = JSON.stringify({method: this, args: args});
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

export default api;
