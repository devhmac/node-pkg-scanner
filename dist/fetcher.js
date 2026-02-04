"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CompromisedPackagesFetcher = void 0;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const os = __importStar(require("os"));
const node_fetch_1 = __importDefault(require("node-fetch"));
class CompromisedPackagesFetcher {
    constructor() {
        this.cacheDir = path.join(os.tmpdir(), 'node-pkg-scanner');
        this.cacheFile = path.join(this.cacheDir, 'compromised-packages.txt');
        this.ensureCacheDir();
    }
    async fetchCompromisedPackages(url, cacheTimeoutMinutes, additionalPackages = []) {
        let packages;
        let usingCache = false;
        try {
            // Try to fetch from remote first
            console.log(`Fetching compromised packages from: ${url}`);
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout
            const response = await (0, node_fetch_1.default)(url, {
                signal: controller.signal,
                headers: {
                    'User-Agent': 'node-pkg-scanner/1.0.0'
                }
            });
            clearTimeout(timeoutId);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            const content = await response.text();
            packages = this.parsePackageList(content);
            // Cache the successful fetch
            this.writeCache(content);
            console.log(`✓ Successfully fetched ${packages.size} compromised packages from remote`);
        }
        catch (error) {
            console.warn(`⚠️  Failed to fetch from remote: ${error}`);
            console.log('Attempting to use cached version...');
            const cachedContent = this.readCache(cacheTimeoutMinutes);
            if (cachedContent) {
                packages = this.parsePackageList(cachedContent);
                usingCache = true;
                console.log(`✓ Using cached list with ${packages.size} compromised packages`);
            }
            else {
                console.error('❌ No valid cache available');
                // Fall back to embedded list as last resort
                packages = this.getEmbeddedPackages();
                usingCache = true;
                console.log(`✓ Using embedded fallback list with ${packages.size} compromised packages`);
            }
        }
        // Add additional packages from config (without versions for now)
        additionalPackages.forEach(pkg => {
            const trimmedPkg = pkg.trim();
            if (!packages.has(trimmedPkg)) {
                packages.set(trimmedPkg, []); // No specific versions for additional packages
            }
        });
        if (additionalPackages.length > 0) {
            console.log(`✓ Added ${additionalPackages.length} additional packages from config`);
        }
        return { packages, usingCache };
    }
    parsePackageList(content) {
        const packageMap = new Map();
        content
            .split(/\r?\n/)
            .map(line => line.trim())
            .filter(line => line && !line.startsWith('#'))
            .forEach(line => {
            const colonIndex = line.indexOf(':');
            if (colonIndex > 0) {
                // Handle package:version format
                const packageName = line.substring(0, colonIndex);
                const version = line.substring(colonIndex + 1);
                if (!packageMap.has(packageName)) {
                    packageMap.set(packageName, []);
                }
                packageMap.get(packageName).push(version);
            }
            else {
                // Handle package name only (for additional packages)
                if (!packageMap.has(line)) {
                    packageMap.set(line, []);
                }
            }
        });
        return packageMap;
    }
    ensureCacheDir() {
        if (!fs.existsSync(this.cacheDir)) {
            fs.mkdirSync(this.cacheDir, { recursive: true });
        }
    }
    writeCache(content) {
        try {
            const cacheData = {
                timestamp: Date.now(),
                content
            };
            fs.writeFileSync(this.cacheFile, JSON.stringify(cacheData));
        }
        catch (error) {
            console.warn(`Warning: Could not write cache: ${error}`);
        }
    }
    readCache(timeoutMinutes) {
        try {
            if (!fs.existsSync(this.cacheFile)) {
                return null;
            }
            const cacheContent = fs.readFileSync(this.cacheFile, 'utf8');
            const cacheData = JSON.parse(cacheContent);
            const ageMinutes = (Date.now() - cacheData.timestamp) / (1000 * 60);
            if (ageMinutes > timeoutMinutes) {
                console.log(`Cache is ${Math.round(ageMinutes)} minutes old (timeout: ${timeoutMinutes})`);
                return null;
            }
            return cacheData.content;
        }
        catch (error) {
            console.warn(`Warning: Could not read cache: ${error}`);
            return null;
        }
    }
    getEmbeddedPackages() {
        // Embedded fallback list based on known Shai Hulud packages
        const embeddedPackages = [
            'cr0wdstrike-fix',
            'crowdstrike-update',
            'crowdstrike-emergency-fix',
            'crowdstrike-fix-update',
            'crowdstrik-update',
            'croudstrike-fix',
            'crowdstrike-falcon-fix',
            'crowdstrikefix'
        ];
        const packageMap = new Map();
        embeddedPackages.forEach(pkg => {
            packageMap.set(pkg, []); // No specific versions for embedded packages
        });
        return packageMap;
    }
}
exports.CompromisedPackagesFetcher = CompromisedPackagesFetcher;
