const axios = require("axios");

const API_KEY = "20b6641e538384c7cb73da6530ab1cbd63ce8d8f365b51efce5ec9b5ad1a2068";

async function checkVirusTotal(url){

    try{

        const response = await axios.post(
            "https://www.virustotal.com/api/v3/urls",
            `url=${encodeURIComponent(url)}`,
            {
                headers:{
                    "x-apikey":API_KEY,
                    "Content-Type":"application/x-www-form-urlencoded"
                }
            }
        );

        const analysisId=response.data.data.id;

        const result=await axios.get(
            `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
            {
                headers:{
                    "x-apikey":API_KEY
                }
            }
        );

        const stats=result.data.data.attributes.stats;

        const malicious=stats.malicious || 0;

        if(malicious>0){

            return{
                score:5,
                indicator:`VirusTotal flagged by ${malicious} security engines`
            };

        }

        return{score:0,indicator:null};

    }catch(error){

        return{score:0,indicator:null};

    }

}

module.exports={checkVirusTotal};