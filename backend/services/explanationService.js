const explanations = {

"Website not using HTTPS":
"Legitimate websites typically use HTTPS encryption. Phishing sites often avoid HTTPS or use misconfigured certificates.",

"URL contains @ symbol":
"The '@' symbol can hide the real destination of a URL and is commonly used in phishing attacks.",

"URL uses IP address instead of domain name":
"Phishing sites sometimes use raw IP addresses to avoid domain registration tracking.",

"URL has excessive subdomains":
"Phishing sites often create long subdomains to imitate legitimate services.",

"Domain registered recently":
"Phishing websites frequently use newly registered domains to avoid detection.",

"Suspicious top-level domain used":
"Certain top-level domains such as .xyz, .tk, and .top are frequently abused in phishing campaigns.",

"Possible impersonation":
"Attackers often include well-known brand names in malicious domains to trick users into trusting the site.",

"Login form detected":
"Phishing sites often include login forms to steal user credentials.",

"Website contains iframe elements":
"Iframes can be used to load hidden malicious content.",

"Large number of external scripts":
"Phishing pages may load multiple external scripts to execute malicious behavior.",

"Shortened URL found in email":
"URL shortening services can hide the true destination of malicious links.",

"Reply-To address differs from sender":
"Phishing emails often spoof the sender but redirect replies to attacker-controlled addresses."

};

function generateExplanation(indicators){

return indicators.map(indicator=>{

for(let key in explanations){

if(indicator.includes(key)){
return explanations[key];
}

}

return "This indicator suggests potentially suspicious behavior.";

});

}

module.exports={generateExplanation};