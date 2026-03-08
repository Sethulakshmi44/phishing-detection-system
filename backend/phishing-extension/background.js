chrome.runtime.onInstalled.addListener(()=>{

chrome.contextMenus.create({
id:"scanLink",
title:"Scan for phishing",
contexts:["link"]
});

});

chrome.contextMenus.onClicked.addListener(async(info)=>{

if(info.menuItemId==="scanLink"){

const url=info.linkUrl;

const response=await fetch("http://localhost:5000/api/analyze-url",{

method:"POST",
headers:{
"Content-Type":"application/json"
},

body:JSON.stringify({url:url})

});

const result=await response.json();

alert(`Risk Level: ${result.risk_level}`);

}

});