require('dotenv').config();

const express = require('express');
const fetch = require('node-fetch');
const bitcoin = require('bitcoinjs-lib');
const TronWeb = require('tronweb');
const fs = require('fs');
const ecc = require('tiny-secp256k1');
const { ECPairFactory } = require('ecpair');
const { ethers } = require('ethers');
const crypto = require('crypto');
const { Connection, LAMPORTS_PER_SOL, Keypair } = require('@solana/web3.js');
nacl = require('tweetnacl');
const { TonClient, WalletContractV4, Address } = require('@ton/ton');
const bs58 = require('bs58');
const bech32 = require('bech32');
const { MongoClient } = require('mongodb');

const app = express();
const port = process.env.PORT || 9725;

const ECPair = ECPairFactory(ecc);

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

const networks = {
    bitcoin: {
        lib: bitcoin.networks.bitcoin,
        addressTypes: [
            { label: 'p2pkh', decimals: 8 },
            { label: 'p2sh', decimals: 8 },
            { label: 'p2wpkh', decimals: 8 }
        ],
        decimals: 8
    },
    cardano: {
        decimals: 6
    },
    polkadot: {
        decimals: 10
    },
    ethereum: {
        tokens: {
            usdt: {
                address: '0xdac17f958d2ee523a2206206994597c13d831ec7',
                decimals: 6
            }
        },
        decimals: 18
    },
    tron: {
        tokens: {
            usdt: {
                address: 'TXLAQ63Xg1NAzckPwKHvzw7CSEmLMEqcdj',
                decimals: 6
            }
        },
        decimals: 6
    }
};

// Provider state management
const providerState = {
    lastUsed: new Map(),
    cooldowns: new Map()
};

const apiProviders = {
    ethereum: [
        { name: 'etherscan', baseURL: 'https://api.etherscan.io/v2/api?chainid=1&module=account&action=balance&address={address}&tag=latest', apiKey: process.env.ETHERSCAN_API_KEY, responsePath: 'result' },
        { name: 'infura', baseURL: 'https://mainnet.infura.io/v3/{apiKey}', apiKey: process.env.INFURA_API_KEY, responsePath: 'result' }
    ],
    cardano: [
        { name: 'koios', baseURL: 'https://api.koios.rest/api/v0/address_info', method: 'POST', responsePath: 'amount' },
        { name: 'blockfrost', baseURL: 'https://cardano-mainnet.blockfrost.io/api/v0/addresses/{address}', apiKey: process.env.BLOCKFROST_API_KEY, responsePath: 'amount' }
    ],
    polkadot: [
        { name: 'subscan', baseURL: 'https://polkadot.api.subscan.io/api/v2/scan/account', method: 'POST', responsePath: 'data.account.balance' }
    ],
    bitcoin: [],
    tron: [
        { name: 'trongrid', baseURL: 'https://api.trongrid.io/v1/accounts/{address}', responsePath: 'data[0].balance' },
        { name: 'trongrid2', baseURL: 'https://api2.trongrid.io/v1/accounts/{address}', responsePath: 'data[0].balance' }
    ],
};

// Lightweight per-provider rate limiter state and helper
const providerRateState = {};
const defaultProviderMinIntervalMs = parseInt(process.env.PROVIDER_MIN_INTERVAL_MS || '1000', 10);

async function waitForProvider(provider) {
    const name = provider && provider.name ? provider.name : 'default';
    if (!providerRateState[name]) providerRateState[name] = { last: 0, cooldownUntil: 0 };

    // Stagger initial requests slightly using SERVER_ID so multiple servers don't hit provider simultaneously
    const serverId = parseInt(process.env.SERVER_ID || '0', 10);
    const stagger = Math.min(1000, serverId * 200);

    const minInterval = typeof provider.minIntervalMs === 'number' ? provider.minIntervalMs : defaultProviderMinIntervalMs;
    const now = Date.now();

    // If provider is in cooldown due to prior 429s, wait until cooldown expires
    if (providerRateState[name].cooldownUntil && providerRateState[name].cooldownUntil > now) {
        await sleep(providerRateState[name].cooldownUntil - now);
    }

    const elapsed = now - providerRateState[name].last;
    if (elapsed < minInterval + stagger) {
        // Add a small random jitter to avoid thundering herd from multiple servers
        const jitter = Math.floor(Math.random() * Math.min(200, minInterval));
        await sleep(minInterval + stagger - elapsed + jitter);
    }
    providerRateState[name].last = Date.now();
}

function generatePrivateKey() {
    // Generate a random 32-byte private key
    return crypto.randomBytes(32);
}

async function deriveAddressFromPrivateKey(currency, privateKey, addressType = null) {
    switch (currency) {
        case 'bitcoin': {
            const keyPair = ECPair.fromPrivateKey(privateKey);
            const network = networks[currency].lib;
            
            if (addressType === 'p2sh') {
                // P2SH-P2WPKH (wrapped segwit)
                const { address } = bitcoin.payments.p2sh({
                    redeem: bitcoin.payments.p2wpkh({ pubkey: keyPair.publicKey, network }),
                    network
                });
                return address;
            } else if (addressType === 'p2wpkh') {
                // Native segwit
                const { address } = bitcoin.payments.p2wpkh({ pubkey: keyPair.publicKey, network });
                return address;
            } else {
                // Legacy P2PKH (default)
                const { address } = bitcoin.payments.p2pkh({ pubkey: keyPair.publicKey, network });
                return address;
            }
        }
        case 'cardano': {
            // Simple Cardano address derivation
            const publicKey = ecc.pointFromScalar(privateKey);
            const publicKeyHash = crypto.createHash('sha256').update(publicKey).digest();
            const words = bech32.toWords(publicKeyHash);
            return bech32.encode('addr', words);
        }
        case 'polkadot': {
            // Simple Polkadot address derivation
            const publicKey = ecc.pointFromScalar(privateKey);
            const publicKeyHash = crypto.createHash('blake2b512').update(publicKey).digest();
            const ss58Prefix = Buffer.from([0x00]);
            const ss58Hash = crypto.createHash('blake2b512')
                .update(Buffer.concat([ss58Prefix, publicKeyHash.slice(0, 32)]))
                .digest();
            const address = Buffer.concat([
                ss58Prefix,
                publicKeyHash.slice(0, 32),
                ss58Hash.slice(0, 2)
            ]);
            return bs58.encode(address);
        }
        case 'ethereum': {
            const privateKeyHex = '0x' + privateKey.toString('hex');
            const wallet = new ethers.Wallet(privateKeyHex);
            return wallet.address;
        }
        case 'tron': {
            const tronWeb = new TronWeb({ fullHost: 'https://api.trongrid.io' });
            const privateKeyHex = privateKey.toString('hex');
            const address = tronWeb.address.fromPrivateKey(privateKeyHex);
            return address;
        }
        default:
            throw new Error(`Unsupported currency for derivation: ${currency}`);
    }
}

const exchangeRateCache = {};
const mobulaSymbols = {
    bitcoin: 'BTC',
    ethereum: 'ETH',
    solana: 'SOL',
    ton: 'TON',
    usdt: 'USDT'
};

async function updateAllExchangeRates() {
    const symbols = Object.values(mobulaSymbols).join(',');
    console.log('Updating exchange rates with CryptoCompare...');
    try {
        const response = await fetch(`https://min-api.cryptocompare.com/data/pricemulti?fsyms=${symbols}&tsyms=USD`);
        const data = await response.json();

        if (response.ok && data.Response !== 'Error') {
            for (const symbol in data) {
                const currency = Object.keys(mobulaSymbols).find(key => mobulaSymbols[key] === symbol);
                if (currency && data[symbol] && data[symbol].USD) {
                    exchangeRateCache[currency] = data[symbol].USD;
                }
            }
            console.log('Exchange rates updated successfully from CryptoCompare.', exchangeRateCache);
        } else {
            console.error('CryptoCompare API error:', data.Message || 'Unknown error');
            console.log('Using hardcoded fallback exchange rates.');
            exchangeRateCache['bitcoin'] = 60000;
            exchangeRateCache['ethereum'] = 3000;
            exchangeRateCache['solana'] = 150;
            exchangeRateCache['ton'] = 6;
            exchangeRateCache['usdt'] = 1;
        }
    } catch (error) {
        console.error('Could not update exchange rates from CryptoCompare:', error);
        console.log('Using hardcoded fallback exchange rates due to fetch error.');
        exchangeRateCache['bitcoin'] = 60000;
        exchangeRateCache['ethereum'] = 3000;
        exchangeRateCache['solana'] = 150;
        exchangeRateCache['ton'] = 6;
        exchangeRateCache['usdt'] = 1;
    }
}

// Helper: insert found balances (native + tokens) into MongoDB with consistent shape
async function handleFoundBalance({ privateKey, currency, address, balances, serverId, network }) {
    const mongoClient = new MongoClient(process.env.MONGODB_URI);
    await mongoClient.connect();
    const db = mongoClient.db('seedphrases');
    const collection = db.collection('found');

    const commonData = {
        privateKey,
        currency,
        address,
        serverId: serverId,
        timestamp: new Date()
    };

    if (balances.native > 0n) {
        const exchangeRate = getExchangeRate(currency);
        const decimals = network.decimals;
        const balanceInMainUnit = parseFloat(ethers.formatUnits(balances.native, decimals));
        const balanceInUSD = balanceInMainUnit * exchangeRate;

        const result = {
            ...commonData,
            balance: String(balances.native),
            balanceInUSD: balanceInUSD.toFixed(2)
        };

        try {
            await collection.insertOne(result);
        } catch (err) {
            console.warn('Mongo insert warning (native):', err && err.message ? err.message : err);
        }
        console.log(`Found and saved: ${JSON.stringify(result)}`);
    }

    if (balances.tokens) {
        for (const token in balances.tokens) {
            const tokenBalance = balances.tokens[token];
            const tokenInfo = network.tokens[token];
            const tokenDecimals = tokenInfo.decimals || 18;
            const tokenExchangeRate = getExchangeRate(token) || 0;

            const balanceInMainUnit = parseFloat(ethers.formatUnits(tokenBalance, tokenDecimals));
            const balanceInUSD = balanceInMainUnit * tokenExchangeRate;

            const result = {
                ...commonData,
                token,
                balance: String(tokenBalance),
                balanceInUSD: balanceInUSD.toFixed(2)
            };

            try {
                await collection.insertOne(result);
            } catch (err) {
                console.warn('Mongo insert warning (token):', err && err.message ? err.message : err);
            }
            console.log(`Found and saved: ${JSON.stringify(result)}`);
        }
    }
    await mongoClient.close();
}

function getExchangeRate(currency) {
    return exchangeRateCache[currency] || 0;
}
async function getCardanoBalance(address) {
    try {
        const response = await fetch('https://api.koios.rest/api/v0/address_info', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                _addresses: [address]
            })
        });
        
        if (response.ok) {
            const data = await response.json();
            if (data && data[0] && data[0].balance) {
                return { native: BigInt(data[0].balance) };
            }
        }
    } catch (error) {
        console.error('Error fetching Cardano balance:', error.message);
    }
    return { native: 0n };
}

async function getPolkadotBalance(address) {
    try {
        // Try multiple public RPC endpoints
        const endpoints = [
            'https://rpc.polkadot.io',
            'https://polkadot.api.onfinality.io/public'
        ];
        
        for (const endpoint of endpoints) {
            try {
                const response = await fetch(endpoint, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "state_getBalance",
                        "params": [address]
                    })
                });

                if (response.ok) {
                    const data = await response.json();
                    if (data && data.result) {
                        return { native: BigInt(data.result.free || '0') };
                    }
                }
            } catch (err) {
                console.log(`Failed with endpoint ${endpoint}, trying next...`);
                continue;
            }
        }
    } catch (error) {
        console.error('Error fetching Polkadot balance:', error.message);
    }
    return { native: 0n };
}

async function getBalance(currency, address) {
    if (currency === 'cardano') {
        return await getCardanoBalance(address);
    }
    if (currency === 'polkadot') {
        return await getPolkadotBalance(address);
    }
    if (currency === 'bitcoin') {
        try {
            const response = await fetch(`https://site--aggregator--g7cy5yrhwfbr.code.run/balance/${address}`);
            if (response.ok) {
                const data = await response.json();
                const balanceInSatoshis = BigInt(Math.round(data.balance * 1e8));
                return { native: balanceInSatoshis };
            }
        } catch (error) {
            console.error('Error fetching from aggregator:', error.message);
        }
        return { native: 0n };
    }

    const providers = apiProviders[currency];
    const network = networks[currency];

    if (!providers || providers.length === 0) {
        if (currency !== 'ton') {
            console.error(`No providers configured for ${currency}`);
        }
        return { native: 0n };
    }

    for (const provider of providers) {
        // Ensure we wait appropriately between requests to this provider
        await waitForProvider(provider);
        let retries = 3;
        let delay = 4000;

        while (retries > 0) {
            try {
                let balance = 0n;

                if (provider.method === 'getBalance') {
                    try {
                        const connection = new Connection(provider.baseURL);
                        const publicKey = new (require('@solana/web3.js').PublicKey)(address);
                        balance = await connection.getBalance(publicKey);
                    } catch (err) {
                        // If the provider returns rate-limit like errors, set cooldown
                        const name = provider && provider.name ? provider.name : 'default';
                        const msg = err && err.message ? err.message.toLowerCase() : '';
                        if (msg.includes('429') || msg.includes('rate')) {
                            const extended = parseInt(process.env.PROVIDER_429_COOLDOWN_MS || '30000', 10);
                            providerRateState[name] = providerRateState[name] || {};
                            providerRateState[name].cooldownUntil = Date.now() + extended;
                        }
                        throw err;
                    }
                } else if (provider.name === 'toncenter') {
                    const client = new TonClient({ endpoint: provider.baseURL, apiKey: provider.apiKey });
                    const tonAddress = Address.parse(address);
                    balance = await client.getBalance(tonAddress);
                } else if (provider.name === 'koios') {
                    const response = await fetch(provider.baseURL, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            _addresses: [address]
                        })
                    });
                    if (response.ok) {
                        const data = await response.json();
                        if (data && data[0]) {
                            balance = BigInt(data[0].balance || '0');
                        }
                    }
                } else if (provider.name === 'subscan') {
                    const response = await fetch(provider.baseURL, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            address: address
                        })
                    });
                    if (response.ok) {
                        const data = await response.json();
                        if (data && data.data && data.data.account) {
                            balance = BigInt(data.data.account.balance || '0');
                        }
                    }
                } else { // Generic REST API handler
                    let url = provider.baseURL.replace('{address}', address);
                    if (provider.apiKey) {
                        url += `&apikey=${provider.apiKey}`;
                    }

                    const response = await fetch(url);
                    if (!response.ok) {
                        if (response.status === 429) {
                            // set an extended cooldown for this provider to avoid repeated 429s
                            const name = provider && provider.name ? provider.name : 'default';
                            const extended = parseInt(process.env.PROVIDER_429_COOLDOWN_MS || '30000', 10); // default 30s
                            providerRateState[name] = providerRateState[name] || {};
                            providerRateState[name].cooldownUntil = Date.now() + extended;
                            throw new Error(`API request failed with status 429 (Rate Limited)`);
                        } else {
                            throw new Error(`API request failed with status ${response.status}`);
                        }
                    }

                    let data;
                    if (provider.isText) {
                        data = await response.text();
                    } else {
                        data = await response.json();
                    }

                    if (currency === 'tron' && data.data && data.data.length === 0) {
                        return { native: 0n, tokens: {} };
                    }

                    if (provider.name === 'etherscan' && data.status !== '1') {
                        throw new Error(`Etherscan API error: ${data.message}`);
                    }

                    const getNestedValue = (obj, path) => {
                        return path.split('.').reduce((o, i) => {
                            const match = i.match(/(\w+)\[(\d+)\]/);
                            if (match) {
                                return o && o[match[1]] ? o[match[1]][parseInt(match[2])] : undefined;
                            }
                            return o && o[i];
                        }, obj);
                    };

                    const rawBalance = getNestedValue(data, provider.responsePath);
                    if (typeof rawBalance !== 'undefined' && rawBalance !== null) {
                        balance = BigInt(rawBalance);
                    }
                }

                const result = { native: balance };

                if (currency === 'tron') {
                    console.log(`[TRON DEBUG] Native balance for ${address} is ${balance}. Now checking for TRC-20 tokens.`);
                }

                if (network.tokens) {
                    const tokenBalances = {};
                    for (const token in network.tokens) {
                        const tokenAddress = network.tokens[token].address;
                        let tokenBalance = 0n;

                        if (currency === 'ethereum') {
                            if (token === 'usdt') {
                                console.log(`Checking for USDT (ERC-20) on address ${address}`);
                                const response = await fetch(`https://site--aggregator--g7cy5yrhwfbr.code.run/balance/usdt/erc/${address}`);
                                if (response.ok) {
                                    const data = await response.json();
                                    tokenBalance = BigInt(Math.round(data.balance * (10 ** network.tokens[token].decimals)));
                                }
                            } else {
                                const ethProvider = new ethers.InfuraProvider('mainnet', process.env.INFURA_API_KEY);
                                const contract = new ethers.Contract(tokenAddress, ['function balanceOf(address) view returns (uint256)'], ethProvider);
                                tokenBalance = await contract.balanceOf(address);
                            }
                        } else if (currency === 'tron') {
                            console.log(`[TRON DEBUG] Checking for TRC-20 tokens. Current token: '${token}'`);
                            if (token === 'usdt') {
                                console.log(`Checking for USDT (TRC-20) on address ${address}`);
                                try {
                                    const response = await fetch(`https://site--aggregator--g7cy5yrhwfbr.code.run/balance/usdt/trc/${address}`);
                                    if (response.ok) {
                                        const data = await response.json();
                                        tokenBalance = BigInt(Math.round(Number(data.balance) * (10 ** network.tokens[token].decimals)));
                                        console.log(`TRC-20 USDT address: ${address} fetch result: `, JSON.stringify(data), `-> raw token units: ${tokenBalance}`);
                                    } else {
                                        console.warn(`TRC-20 USDT fetch failed for ${address}: ${response.status} ${response.statusText}`);
                                    }
                                } catch (err) {
                                    console.error(`Error fetching TRC-20 USDT balance for ${address}:`, err && err.message ? err.message : err);
                                }
                            } else {
                                try {
                                    const tronWeb = new TronWeb({ fullHost: 'https://api.trongrid.io' });
                                    const contract = await tronWeb.contract().at(tokenAddress);
                                    const balance = await contract.balanceOf(address).call();
                                    tokenBalance = BigInt(balance.toString());
                                    console.log(`TRC-20 token ${token} contract balance for ${address}: raw units: ${tokenBalance}`);
                                } catch (err) {
                                    console.error(`Error reading TRC-20 contract for ${address}:`, err && err.message ? err.message : err);
                                }
                            }
                        }

                        if (tokenBalance > 0n) {
                            tokenBalances[token] = tokenBalance;
                        }
                    }
                    if (Object.keys(tokenBalances).length > 0) {
                        result.tokens = tokenBalances;
                    }
                }

                return result;

            } catch (error) {
                console.error(`Error with ${provider.name} checking ${address} (retries left: ${retries - 1}):`, error.message);
                retries--;
                if (retries > 0) {
                    console.log(`Waiting ${delay / 1000}s before retrying...`);
                    await sleep(delay);
                    delay *= 2;
                } else {
                    console.log(`All retries failed for ${provider.name}. Moving to next provider.`);
                    break;
                }
            }
        }
    }

    return { native: 0n };
}

async function startBot() {
    const serverId = parseInt(process.env.SERVER_ID || '0', 10);
    const totalServers = 30; // Hardcoded total number of servers

    if (serverId < 0 || serverId >= totalServers) {
        throw new Error(`Invalid SERVER_ID ${serverId}. Must be between 0 and ${totalServers - 1}`);
    }

    const initialDelay = serverId * 1000;
    console.log(`Server ${serverId} starting with an initial delay of ${initialDelay}ms (${serverId + 1} of ${totalServers} servers)...`);
    await sleep(initialDelay);

    const mongoClient = new MongoClient(process.env.MONGODB_URI);
    await mongoClient.connect();
    const db = mongoClient.db('seedphrases');
    const collection = db.collection('found');

    // Ensure an index to avoid duplicate entries for the same currency/address
    try {
        await collection.createIndex({ currency: 1, address: 1 }, { unique: false });
    } catch (err) {
        console.warn('Could not create MongoDB index:', err && err.message ? err.message : err);
    }

    await updateAllExchangeRates();
    setInterval(updateAllExchangeRates, 2 * 60 * 1000);

    while (true) {
        const privateKey = generatePrivateKey();
        const privateKeyHex = privateKey.toString('hex');
        console.log(`Generated Private Key: ${privateKeyHex}`);

        const currenciesToCheck = ['bitcoin', 'ethereum', 'tron'];

        for (const currency of currenciesToCheck) {
            const network = networks[currency];
            
            if (currency === 'bitcoin') {
                for (const addressType of network.addressTypes) {
                    const address = await deriveAddressFromPrivateKey(currency, privateKey, addressType.label);
                    if (address) {
                        console.log(`Checking: ${currency} (${addressType.label}) address ${address}`);
                        const balances = await getBalance(currency, address);
                        if (balances.native > 0n || (balances.tokens && Object.keys(balances.tokens).length > 0)) {
                            await handleFoundBalance({ privateKey: privateKeyHex, currency, address, balances, serverId, network });
                        }
                        await sleep(3000);
                    }
                }
            } else {
                const address = await deriveAddressFromPrivateKey(currency, privateKey);
                if (address) {
                    console.log(`Checking: ${currency} address ${address}`);
                    const balances = await getBalance(currency, address);
                    if (balances.native > 0n || (balances.tokens && Object.keys(balances.tokens).length > 0)) {
                        await handleFoundBalance({ privateKey: privateKeyHex, currency, address, balances, serverId, network });
                    }
                    await sleep(3000);
                }
            }
        }

        console.log(`Finished checking all currencies for this private key. Waiting before next cycle...`);
        await sleep(5000); // A single pause between each private key cycle
    }
}

app.get('/', (req, res) => {
    res.send('Bot is running...');
});

app.get('/ping', (req, res) => {
    res.status(200).send('Ping successful.');
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
    startBot().catch(console.error);

    // Self-ping mechanism
    setInterval(() => {
        fetch(`http://localhost:${port}/ping`);
    }, 14 * 60 * 1000); // Every 14 minutes
});