const providers = new Map();

class ProviderRotation {
    constructor() {
        this.lastUsedIndex = new Map();
        this.cooldowns = new Map();
    }

    getNextProvider(currency) {
        const availableProviders = providers.get(currency) || [];
        if (availableProviders.length === 0) return null;

        const now = Date.now();
        let currentIndex = this.lastUsedIndex.get(currency) || 0;
        let attempts = 0;

        while (attempts < availableProviders.length) {
            currentIndex = (currentIndex + 1) % availableProviders.length;
            const provider = availableProviders[currentIndex];
            const cooldownKey = `${currency}-${provider.name}`;
            const cooldownUntil = this.cooldowns.get(cooldownKey) || 0;

            if (now >= cooldownUntil) {
                this.lastUsedIndex.set(currency, currentIndex);
                return provider;
            }

            attempts++;
        }

        return null; // All providers are in cooldown
    }

    setCooldown(currency, providerName, duration) {
        const cooldownKey = `${currency}-${providerName}`;
        const cooldownUntil = Date.now() + duration;
        this.cooldowns.set(cooldownKey, cooldownUntil);
    }

    registerProviders(currency, providersList) {
        providers.set(currency, providersList);
    }
}

module.exports = new ProviderRotation();