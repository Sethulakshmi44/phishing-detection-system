const PDFDocument = require("pdfkit");

function generatePDFReport(data, res) {

  const doc = new PDFDocument();

  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", "attachment; filename=phishing-report.pdf");

  doc.pipe(res);

  // 🔹 Title
  doc.fontSize(18).text("Phishing Detection Report", { align: "center" });
  doc.moveDown();

  // 🔹 Basic Info
  doc.fontSize(12).text(`URL: ${data.url}`);
  doc.text(`Risk Level: ${data.risk_level}`);
  doc.text(`Phishing Score: ${data.phishing_score}`);
  doc.moveDown();

  // 🔹 Indicators
  doc.fontSize(14).text("Indicators:");
  doc.moveDown(0.5);

  if (data.indicators && data.indicators.length > 0) {
    data.indicators.forEach(ind => {
      doc.text(`- ${ind}`);
    });
  } else {
    doc.text("No suspicious indicators found.");
  }

  doc.moveDown();

  // 🔹 Explanations
  doc.fontSize(14).text("Explanations:");
  doc.moveDown(0.5);

  if (data.explanations && data.explanations.length > 0) {
    data.explanations.forEach(exp => {
      doc.text(`- ${exp}`);
    });
  }

  doc.moveDown();

  // 🔹 Breakdown
  doc.fontSize(14).text("Detection Breakdown:");
  doc.moveDown(0.5);

  if (data.breakdown) {
    doc.text(`URL Analysis: ${data.breakdown.url}`);
    doc.text(`Domain Intelligence: ${data.breakdown.domain}`);
    doc.text(`Website Analysis: ${data.breakdown.website}`);
    doc.text(`Threat Intelligence: ${data.breakdown.threat}`);
  }

  doc.end();
}

module.exports = { generatePDFReport };