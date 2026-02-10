const ExcelJS = require('exceljs');
const path = require('path');

async function checkTemplate() {
    const workbook = new ExcelJS.Workbook();
    const filePath = path.join(__dirname, 'MasterFile', 'Yearly Individual Attendance Detail.xlsx');

    try {
        await workbook.xlsx.readFile(filePath);

        console.log(`File: ${filePath}`);
        console.log(`Sheet Count: ${workbook.worksheets.length}`);

        workbook.eachSheet((worksheet, sheetId) => {
            console.log(`\n--- Sheet ${sheetId}: ${worksheet.name} ---`);
            worksheet.eachRow((row, rowNumber) => {
                if (rowNumber > 5) return; // First 5 rows only
                console.log(`Row ${rowNumber}: ${JSON.stringify(row.values)}`);
            });
        });

    } catch (err) {
        console.error("Error reading file:", err);
    }
}

checkTemplate();
