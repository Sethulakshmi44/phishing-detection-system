const axios=require("axios");
const fs=require("fs");

const urls=fs.readFileSync("../datasets/test_urls.txt","utf8").split("\n");

async function test(){

for(let url of urls){

    try{

        const result=await axios.post(
        "http://localhost:5000/api/analyze-url",
        {url:url}
        );

        console.log(url,result.data.risk_level);

    }catch(e){}

}

}

test();