const ExcelJS = require('exceljs');
const path = require('path');

async function checkTemplate() {
    const workbook = new ExcelJS.Workbook();
    const filePath = path.join(__dirname, 'MasterFile', 'Export All Attendances.xlsx');

    try {
        await workbook.xlsx.readFile(filePath);
        const worksheet = workbook.worksheets[0];
        console.log(`Sheet Name: ${worksheet.name}`);

        console.log('--- First 10 Rows ---');
        worksheet.eachRow((row, rowNumber) => {
            if (rowNumber > 10) return;
            console.log(`Row ${rowNumber}: ${JSON.stringify(row.values)}`);
        });

    } catch (err) {
        console.error("Error reading file:", err);
    }
}

checkTemplate();
