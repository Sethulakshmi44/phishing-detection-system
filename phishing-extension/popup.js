document.getElementById("scanBtn").addEventListener("click", async () => {

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    chrome.scripting.executeScript({
        target: { tabId: tab.id },
        function: extractEmailContent
    }, async (results) => {

        const content = results[0].result;

        fetch("http://localhost:5000/api/download-report", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: content })
})

        const response = await fetch("http://localhost:5000/api/analyze-email", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: content })
        });

        const data = await response.json();

        const score = data.phishing_score || 0;
const risk = data.risk_level || "Low Risk";

document.getElementById("result").innerText =
    `Score: ${score} | Risk: ${risk}`;
    });

});

// 🔹 Extract visible email content from Gmail
function extractEmailContent() {

    const emailBody = document.querySelector("div[role='main']");
    return emailBody ? emailBody.innerText : "No email content found";

}