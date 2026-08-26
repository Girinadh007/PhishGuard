const fs = require('fs');
const readline = require('readline');
const path = require('path');

const CSV_FILE = path.join(__dirname, '../model/top-1m.csv');
const JSON_FILE = path.join(__dirname, '../model/allowlist.json');
const LIMIT = 100000;

async function buildAllowlist() {
    console.log(`Reading from ${CSV_FILE}...`);
    const fileStream = fs.createReadStream(CSV_FILE);

    const rl = readline.createInterface({
        input: fileStream,
        crlfDelay: Infinity
    });

    const domains = [];
    let count = 0;

    for await (const line of rl) {
        if (count >= LIMIT) break;
        const parts = line.split(',');
        if (parts.length >= 2) {
            domains.push(parts[1].trim());
            count++;
        }
    }

    console.log(`Extracted ${domains.length} domains. Saving to ${JSON_FILE}...`);
    fs.writeFileSync(JSON_FILE, JSON.stringify(domains));
    console.log('Done!');
}

buildAllowlist().catch(console.error);
