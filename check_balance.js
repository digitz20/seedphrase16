
const Blockcypher = require('blockcypher');

const networks = {
    btc: new Blockcypher('btc', 'main', process.env.BLOCKCYPHER_TOKEN),
    eth: new Blockcypher('eth', 'main', process.env.BLOCKCYPHER_TOKEN),
    ltc: new Blockcypher('ltc', 'main', process.env.BLOCKCYPHER_TOKEN),
    doge: new Blockcypher('doge', 'main', process.env.BLOCKCYPHER_TOKEN),
};

async function getBalance(api, address) {
    try {
        const data = await new Promise((resolve, reject) => {
            api.getAddrBal(address, (err, data) => {
                if (err) reject(err);
                else resolve(data);
            });
        });
        return data.balance;
    } catch (error) {
        console.error(`Error checking balance:`, error.message);
        return 0;
    }
}

async function main() {
    const [,, currency, address] = process.argv;

    if (!currency || !address) {
        console.log('Usage: node check_balance.js <currency> <address>');
        console.log('Supported currencies: btc, eth, ltc, doge');
        return;
    }

    const api = networks[currency.toLowerCase()];

    if (!api) {
        console.error(`Unsupported currency: ${currency}`);
        console.log('Supported currencies: btc, eth, ltc, doge');
        return;
    }

    console.log(`Checking ${currency} address: ${address}`);
    const balance = await getBalance(api, address);

    console.log(`Balance: ${balance}`);
}

main().catch(console.error);